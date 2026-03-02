use crate::builder;
use crate::config::SiteConfig;
use anyhow::{Context, Result};
use notify::{Event, RecursiveMode, Watcher};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;

/// Live-reload WebSocket script injected into every HTML page during serve.
const LIVE_RELOAD_SCRIPT: &str = r#"<script>
(function() {
  var ws = new WebSocket('ws://' + location.hostname + ':{{WS_PORT}}');
  ws.onmessage = function(e) { if (e.data === 'reload') location.reload(); };
  ws.onclose = function() {
    setTimeout(function() { location.reload(); }, 2000);
  };
})();
</script>"#;

/// Run the serve command: build, start HTTP + WebSocket servers, watch for changes.
pub fn serve(src: &Path, port: u16, open_browser: bool) -> Result<()> {
    let config = SiteConfig::load(src)?;
    let base_path = config.site.base_path.clone();
    let ws_port = port + 1;

    // Create temp directory for serving
    let tmp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let serve_root = tmp_dir.path().to_path_buf();

    println!("Serving from temp directory: {}", serve_root.display());

    // Initial build
    build_and_copy(src, &serve_root, &base_path, ws_port)?;

    // Track connected WebSocket clients
    let clients: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));

    // Create HTTP and WebSocket listeners upfront with SO_REUSEADDR
    // so that rapid restarts (after Ctrl+C) don't hit "address in use".
    let http_listener = create_reuse_listener(port)
        .with_context(|| format!("Failed to bind HTTP server to port {}", port))?;
    let ws_listener = create_reuse_listener(ws_port)
        .with_context(|| format!("Failed to bind WebSocket server to port {}", ws_port))?;

    // Start WebSocket server for live-reload notifications
    let ws_clients = clients.clone();
    thread::spawn(move || {
        if let Err(e) = run_ws_server(ws_listener, ws_clients) {
            eprintln!("WebSocket server error: {}", e);
        }
    });

    // Start HTTP server
    let http_root = serve_root.clone();
    thread::spawn(move || {
        if let Err(e) = run_http_server(http_listener, &http_root) {
            eprintln!("HTTP server error: {}", e);
        }
    });

    let url = if base_path.is_empty() {
        format!("http://localhost:{}/", port)
    } else {
        format!("http://localhost:{}{}/", port, base_path)
    };

    println!("\n  Local: {}", url);
    println!("  Press Ctrl+C to stop.\n");

    if open_browser {
        let _ = open::that(&url);
    }

    // File watcher
    let (tx, rx) = mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                let _ = tx.send(());
            }
        }
    })?;

    let src_abs = fs::canonicalize(src)?;
    watcher.watch(&src_abs, RecursiveMode::Recursive)?;

    println!("Watching for changes in {}...", src_abs.display());

    // Debounce: wait for changes, then rebuild
    loop {
        // Block until a change notification arrives
        if rx.recv().is_err() {
            break;
        }
        // Drain any additional events within a short debounce window
        thread::sleep(Duration::from_millis(200));
        while rx.try_recv().is_ok() {}

        println!("Change detected, rebuilding...");
        match build_and_copy(src, &serve_root, &base_path, ws_port) {
            Ok(()) => {
                println!("Rebuild complete. Notifying browser...");
                notify_clients(&clients);
            }
            Err(e) => {
                eprintln!("Rebuild failed: {}", e);
            }
        }
    }

    Ok(())
}

/// Build site into a temp build dir, then copy to serve_root/<base_path>/
/// with live-reload script injected.
fn build_and_copy(src: &Path, serve_root: &Path, base_path: &str, ws_port: u16) -> Result<()> {
    // Build into a temporary output directory
    let build_tmp = tempfile::tempdir().context("Failed to create build temp dir")?;
    let build_out = build_tmp.path();

    builder::build(src, build_out)?;

    // Determine the target directory under serve_root
    let target = if base_path.is_empty() {
        serve_root.to_path_buf()
    } else {
        let bp = base_path.trim_start_matches('/');
        serve_root.join(bp)
    };

    // Clean target and copy
    if target.exists() {
        fs::remove_dir_all(&target).ok();
    }
    copy_dir_recursive(build_out, &target)?;

    // Inject live-reload script into all HTML files
    inject_live_reload(&target, ws_port)?;

    Ok(())
}

/// Inject live-reload WebSocket script into all HTML files under dir.
fn inject_live_reload(dir: &Path, ws_port: u16) -> Result<()> {
    let script = LIVE_RELOAD_SCRIPT.replace("{{WS_PORT}}", &ws_port.to_string());

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "html")
        })
    {
        let path = entry.path();
        let content = fs::read_to_string(path)?;
        if let Some(pos) = content.rfind("</body>") {
            let injected = format!("{}{}{}", &content[..pos], script, &content[pos..]);
            fs::write(path, injected)?;
        }
    }

    Ok(())
}

/// Simple HTTP static file server using tiny_http.
fn run_http_server(listener: TcpListener, root: &Path) -> Result<()> {
    let server = tiny_http::Server::from_listener(listener, None)
        .map_err(|e| anyhow::anyhow!("HTTP server: {}", e))?;

    for request in server.incoming_requests() {
        let url_path = percent_decode(request.url());
        let rel = url_path.trim_start_matches('/');

        let file_path = if rel.is_empty() {
            root.join("index.html")
        } else {
            let candidate = root.join(rel);
            if candidate.is_dir() {
                candidate.join("index.html")
            } else {
                candidate
            }
        };

        if file_path.exists() && file_path.is_file() {
            let content = fs::read(&file_path).unwrap_or_default();
            let mime = guess_mime(&file_path);
            let response = tiny_http::Response::from_data(content)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap(),
                );
            let _ = request.respond(response);
        } else {
            let response = tiny_http::Response::from_string("404 Not Found")
                .with_status_code(404);
            let _ = request.respond(response);
        }
    }

    Ok(())
}

/// WebSocket server that accepts connections and stores them for later notification.
fn run_ws_server(listener: TcpListener, clients: Arc<Mutex<Vec<TcpStream>>>) -> Result<()> {

    for stream in listener.incoming().flatten() {
        let clients = clients.clone();
        thread::spawn(move || {
            if let Ok(ws) = tungstenite::accept(stream.try_clone().unwrap()) {
                // Store the underlying TCP stream for later notification
                if let Ok(mut list) = clients.lock() {
                    list.push(stream);
                }
                // Keep the WebSocket connection alive - read until closed
                let mut ws = ws;
                loop {
                    match ws.read() {
                        Ok(msg) => {
                            if msg.is_close() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        });
    }

    Ok(())
}

/// Send "reload" to all connected WebSocket clients.
fn notify_clients(clients: &Arc<Mutex<Vec<TcpStream>>>) {
    if let Ok(mut list) = clients.lock() {
        let mut alive = Vec::new();
        for stream in list.drain(..) {
            if stream.try_clone().is_ok() {
                // Re-wrap as WebSocket and send reload message
                // Since we can't easily re-wrap existing TCP streams,
                // we'll use a simpler approach: raw WebSocket frame
                if send_ws_text_frame(&stream, "reload").is_ok() {
                    alive.push(stream);
                }
            }
        }
        *list = alive;
    }
}

/// Send a WebSocket text frame directly on a TCP stream.
fn send_ws_text_frame(mut stream: &TcpStream, msg: &str) -> Result<()> {
    let payload = msg.as_bytes();
    let len = payload.len();

    // WebSocket text frame: opcode 0x81
    let mut frame = Vec::new();
    frame.push(0x81);
    if len < 126 {
        frame.push(len as u8);
    } else if len < 65536 {
        frame.push(126);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xFF) as u8);
    }
    frame.extend_from_slice(payload);

    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let rel = path.strip_prefix(src)?;
        let target = dst.join(rel);

        if path.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &target)?;
        }
    }
    Ok(())
}

fn guess_mime(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8".to_string(),
        Some("css") => "text/css; charset=utf-8".to_string(),
        Some("js") => "application/javascript; charset=utf-8".to_string(),
        Some("json") => "application/json; charset=utf-8".to_string(),
        Some("svg") => "image/svg+xml".to_string(),
        Some("png") => "image/png".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("gif") => "image/gif".to_string(),
        Some("ico") => "image/x-icon".to_string(),
        Some("wasm") => "application/wasm".to_string(),
        Some("woff") => "font/woff".to_string(),
        Some("woff2") => "font/woff2".to_string(),
        Some("ttf") => "font/ttf".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(|c| hex_val(c));
            let lo = chars.next().and_then(|c| hex_val(c));
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
            }
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Create a TCP listener with SO_REUSEADDR (and SO_REUSEPORT on Unix) set,
/// so that rapid restarts after Ctrl+C don't fail with "address in use".
fn create_reuse_listener(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}
