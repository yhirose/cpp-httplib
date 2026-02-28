---
title: "Getting Started"
order: 1
---

All you need to get started with cpp-httplib is `httplib.h` and a C++ compiler. Let's download the file and get a Hello World server running.

## Getting httplib.h

You can download it directly from GitHub. Always use the latest version.

```sh
curl -LO https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h
```

Place the downloaded `httplib.h` in your project directory and you're good to go.

## Setting Up Your Compiler

| OS | Development Environment | Setup |
| -- | ----------------------- | ----- |
| macOS | Apple Clang | Xcode Command Line Tools (`xcode-select --install`) |
| Ubuntu | clang++ or g++ | `apt install clang` or `apt install g++` |
| Windows | MSVC | Visual Studio 2022 or later (install with C++ components) |

## Hello World Server

Save the following code as `server.cpp`.

```cpp
#include "httplib.h"

int main() {
    httplib::Server svr;

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello, World!", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);
}
```

In just a few lines, you have a server that responds to HTTP requests.

## Compiling and Running

The sample code in this tutorial is written in C++17 for cleaner, more concise code. cpp-httplib itself can compile with C++11 as well.

```sh
# macOS
clang++ -std=c++17 -o server server.cpp

# Linux
# `-pthread`: cpp-httplib uses threads internally
clang++ -std=c++17 -pthread -o server server.cpp

# Windows (Developer Command Prompt)
# `/EHsc`: Enable C++ exception handling
cl /EHsc /std:c++17 server.cpp
```

Once it compiles, run it.

```sh
# macOS / Linux
./server

# Windows
server.exe
```

Open `http://localhost:8080` in your browser. If you see "Hello, World!", you're all set.

You can also verify with `curl`.

```sh
curl http://localhost:8080/
# Hello, World!
```

To stop the server, press `Ctrl+C` in your terminal.

## Next Steps

Now you know the basics of running a server. Next, let's look at the client side. cpp-httplib also comes with HTTP client functionality.

**Next:** [Basic Client](../02-basic-client)
