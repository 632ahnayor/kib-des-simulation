"""
secure_node.py
Bidirectional TCP node that transmits DES-CBC encrypted messages -- this is
test_connection.py's networking/framing layer, with des.py's des_encrypt /
des_decrypt wired into the send/receive path (project task 3.8), plus a
human-readable trace of what happens at each step, printed to the console
AND written to a timestamped log file (task 5).

The log file's timestamps are precise enough (millisecond resolution) to be
cross-referenced against a Wireshark capture of the same session later --
e.g. "at 14:02:31.118 we sent ciphertext starting 478fa7..." should line up
with a packet at that same time on the wire.

This is deliberately developed and testable entirely over localhost (two
processes on one machine). The only thing that changes when this moves onto
the real VM or physical transmission environment is the IP address given on
the command line -- none of the code below needs to change.

Usage:
    Peer A (listens):  python3 secure_node.py server 65432
    Peer B (connects): python3 secure_node.py client 127.0.0.1 65432

Pre-shared key: hardcoded below, per the project's stated scope (no key
distribution/exchange required -- both sides are assumed to already know it).
Type a message and press Enter to send it encrypted; incoming messages are
decrypted automatically and traced. Type 'quit' to exit.
"""

import datetime
import socket
import struct
import sys
import threading

from des import des_encrypt, des_decrypt

# Pre-shared key, known to both sender and receiver ahead of time (8 bytes = 64-bit DES key)
KEY = bytes.fromhex("133457799BBCDFF1")

LOG_FILE = None  # set in __main__ once we know the role, for a distinct filename per run


def log(message: str) -> None:
    """Print with a millisecond timestamp, and append the same line to
    LOG_FILE if one has been set."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{timestamp}] {message}"
    print(line)
    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def send_encrypted(sock: socket.socket, plaintext: str) -> None:
    """Encrypt plaintext, trace it, then send it length-prefixed."""
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = des_encrypt(plaintext_bytes, KEY)  # returns IV || ciphertext

    log(f"[SEND] plaintext  : {plaintext!r}")
    log(f"[SEND] ciphertext : {ciphertext.hex()}  ({len(ciphertext)} bytes, incl. IV)")

    header = struct.pack(">I", len(ciphertext))
    sock.sendall(header + ciphertext)


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        buf += chunk
    return buf


def receive_encrypted(sock: socket.socket):
    """Receive one framed message, trace the raw ciphertext, then decrypt.
    Returns the recovered plaintext string, or None if decryption/integrity
    checking failed (so the caller can distinguish a real message from a
    rejected one without the whole node crashing)."""
    header = recv_exactly(sock, 4)
    (length,) = struct.unpack(">I", header)
    ciphertext = recv_exactly(sock, length)

    log(f"[RECV] ciphertext : {ciphertext.hex()}  ({len(ciphertext)} bytes, incl. IV)")

    try:
        plaintext_bytes = des_decrypt(ciphertext, KEY)
    except ValueError as e:
        log(f"[RECV] DECRYPTION/INTEGRITY FAILURE: {e}")
        return None

    plaintext = plaintext_bytes.decode("utf-8", errors="replace")
    log(f"[RECV] plaintext  : {plaintext!r}")
    return plaintext


def listen_loop(sock: socket.socket) -> None:
    while True:
        try:
            result = receive_encrypted(sock)
        except (ConnectionError, OSError):
            log("[connection closed by peer]")
            break
        if result is not None:
            log(f"[peer said] {result}")
        print("> ", end="", flush=True)


def send_loop(sock: socket.socket) -> None:
    while True:
        text = input("> ")
        if text.strip().lower() == "quit":
            break
        send_encrypted(sock, text)


def run_as_server(port: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(1)
    log(f"[server] listening on port {port}, waiting for peer...")
    conn, addr = listener.accept()
    log(f"[server] connected by {addr}")
    threading.Thread(target=listen_loop, args=(conn,), daemon=True).start()
    send_loop(conn)
    conn.close()
    listener.close()


def run_as_client(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    log(f"[client] connecting to {host}:{port}...")
    sock.connect((host, port))
    log("[client] connected")
    threading.Thread(target=listen_loop, args=(sock,), daemon=True).start()
    send_loop(sock)
    sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 secure_node.py server <port>")
        print("  python3 secure_node.py client <host> <port>")
        sys.exit(1)

    role = sys.argv[1]
    run_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    LOG_FILE = f"log_{role}_{run_timestamp}.txt"
    log(f"logging this session to {LOG_FILE}")

    if role == "server":
        run_as_server(int(sys.argv[2]))
    elif role == "client":
        run_as_client(sys.argv[2], int(sys.argv[3]))
    else:
        print("role must be 'server' or 'client'")
        sys.exit(1)