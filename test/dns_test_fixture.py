#!/usr/bin/env python3
"""Delayed UDP responder used as a loopback test fixture.

This is a self-contained test fixture for the GetAddrInfoAsyncCancelTest
cases (reproducer for cpp-httplib issue #2431). It is NOT a general-purpose
nameserver and is only intended to run on 127.0.0.1 inside the test job's
own runner / container.

What it does
------------
Binds a UDP socket on 127.0.0.1:<port>, accepts well-formed DNS queries
from the test process, waits <delay_seconds>, then sends back a minimal
NXDOMAIN reply. The deliberate delay is what makes the bug reproducible:

  * The test calls getaddrinfo_with_timeout() with timeout_sec=1.
  * gai_suspend() returns EAI_AGAIN after 1s; the function returns and
    its stack frame is destroyed.
  * The fixture replies after <delay_seconds> (= 3s by default), so the
    glibc resolver worker thread receives the response *after* the
    caller's frame is gone and writes back into freed stack memory.
  * AddressSanitizer (with detect_stack_use_after_return=1) catches the
    write and aborts with a stack-use-after-return diagnostic.

Without this fixture the bug is hard to surface: dropping UDP/53 makes
the resolver hang forever, so the worker never receives anything and
never reaches the buggy write-back path.

Usage
-----
    python3 test/dns_test_fixture.py <port> [<delay_seconds>]

Only standard library; no third-party dependencies.
"""

import socket
import struct
import sys
import threading
import time


def serve(port: int, delay_sec: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(
        f"[dns_test_fixture] listening on 127.0.0.1:{port}, "
        f"reply delay={delay_sec}s",
        flush=True,
    )
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            return
        threading.Thread(
            target=_reply_after_delay,
            args=(sock, data, addr, delay_sec),
            daemon=True,
        ).start()


def _reply_after_delay(sock, query: bytes, addr, delay_sec: float) -> None:
    time.sleep(delay_sec)
    if len(query) < 12:
        return
    # Header: copy transaction id, set QR=1 RA=1 RCODE=3 (NXDOMAIN),
    # preserve the requester's RD bit, then echo the question section so
    # glibc's resolver accepts the reply as matching its outstanding query.
    txid = query[:2]
    rd_bit = query[2] & 0x01
    flags = struct.pack(">H", 0x8003 | (rd_bit << 8))
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = query[12:]
    reply = txid + flags + counts + question
    try:
        sock.sendto(reply, addr)
    except OSError:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    port_arg = int(sys.argv[1])
    delay_arg = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    serve(port_arg, delay_arg)
