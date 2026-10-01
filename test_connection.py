"""
test_connection.py
Bare-bones bidirectional TCP connectivity test for the VM-to-VM channel.
Deliberately has NO encryption -- its only job is to prove the network path
and message framing work correctly, in isolation from the DES layer, before
any crypto gets wired in (that happens in a later task).

Usage:
    On the VM acting as server: python3 test_connection.py server 65432
    On the VM acting as client: python3 test_connection.py client <server_ip> 65432

A single TCP connection is used for both directions (sockets are full-duplex
once connected) -- there's no need for two separate connections. Once
connected, either side can type a message and press Enter to send it;
incoming messages from the peer print automatically in the background.
Type 'quit' to exit cleanly.
"""

import socket
import struct
import sys
import threading


def send_message(sock: socket.socket, text: str) -> None:
    """Length-prefix framing: a 4-byte big-endian length header, then the
    UTF-8 payload. This is what lets the receiver know exactly how many
    bytes belong to one message, since TCP itself has no message boundaries."""
    payload = text.encode("utf-8")
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """A single recv() call is NOT guaranteed to return all n requested
    bytes -- it may return fewer. Loop until we actually have them, or the
    connection has closed."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        buf += chunk
    return buf


def receive_message(sock: socket.socket) -> str:
    header = recv_exactly(sock, 4)
    (length,) = struct.unpack(">I", header)
    payload = recv_exactly(sock, length)
    return payload.decode("utf-8")


def listen_loop(sock: socket.socket) -> None:
    """Background thread: print whatever arrives until the peer disconnects."""
    while True:
        try:
            message = receive_message(sock)
        except (ConnectionError, OSError):
            print("\n[connection closed by peer]")
            break
        print(f"\n[peer] {message}\n> ", end="", flush=True)


def send_loop(sock: socket.socket) -> None:
    """Foreground: read from the keyboard and send until 'quit'."""
    while True:
        text = input("> ")
        if text.strip().lower() == "quit":
            break
        send_message(sock, text)


def run_as_server(port: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(1)
    print(f"[server] listening on port {port}, waiting for peer...")
    conn, addr = listener.accept()
    print(f"[server] connected by {addr}")
    threading.Thread(target=listen_loop, args=(conn,), daemon=True).start()
    send_loop(conn)
    conn.close()
    listener.close()


def run_as_client(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[client] connecting to {host}:{port}...")
    sock.connect((host, port))
    print("[client] connected")
    threading.Thread(target=listen_loop, args=(sock,), daemon=True).start()
    send_loop(sock)
    sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 test_connection.py server <port>")
        print("  python3 test_connection.py client <host> <port>")
        sys.exit(1)

    role = sys.argv[1]
    if role == "server":
        run_as_server(int(sys.argv[2]))
    elif role == "client":
        run_as_client(sys.argv[2], int(sys.argv[3]))
    else:
        print("role must be 'server' or 'client'")
        sys.exit(1)