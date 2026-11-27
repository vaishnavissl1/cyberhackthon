"""Live input paths: open pipe, followed file, TCP and HTTP."""
import json
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from hids_agent.agent import file_reader, http_reader, tcp_reader

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(target, *args) -> None:
    threading.Thread(target=target, args=args, daemon=True).start()


def take(q: queue.Queue, n: int, timeout: float = 10) -> list:
    end, out = time.time() + timeout, []
    while len(out) < n:
        out.append(q.get(timeout=max(0.01, end - time.time())))
    return out


def connect(port: int) -> socket.socket:
    end = time.time() + 5
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError:
            if time.time() > end:
                raise
            time.sleep(0.05)


class TestTcp(unittest.TestCase):
    def test_concurrent_clients_get_unique_sequence_numbers(self):
        port, q, counter = free_port(), queue.Queue(), [0]
        start(tcp_reader, f"127.0.0.1:{port}", q, counter)
        connect(port).close()
        clients, per_client = 8, 1500

        def send(c):
            with connect(port) as s:
                s.sendall("".join(json.dumps({"c": c, "i": i}) + "\n" for i in range(per_client)).encode())

        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)   # force thread interleaving so a race would show
        try:
            threads = [threading.Thread(target=send, args=(c,)) for c in range(clients)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            items = take(q, clients * per_client, 60)
        finally:
            sys.setswitchinterval(old)
        self.assertEqual(len({seq for seq, _ in items}), len(items))
        self.assertEqual({(o["c"], o["i"]) for _, o in items},
                         {(c, i) for c in range(clients) for i in range(per_client)})


class TestHttp(unittest.TestCase):
    def setUp(self):
        self.port, self.q = free_port(), queue.Queue()
        start(http_reader, f"127.0.0.1:{self.port}", self.q, [0])
        connect(self.port).close()

    def post(self, body: bytes) -> int:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/", data=body, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status

    def test_jsonl_array_and_single(self):
        self.assertEqual(self.post(b'{"n":1}\n{"n":2}\n'), 204)
        self.assertEqual(self.post(b'[{"n":3},{"n":4}]'), 204)
        self.assertEqual(self.post(b'{\n "n": 5\n}'), 204)
        self.assertEqual([o["n"] for _, o in take(self.q, 5)], [1, 2, 3, 4, 5])

    def test_body_without_length_is_rejected_not_silently_dropped(self):
        with connect(self.port) as s:
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                      b"7\r\n{\"n\":1}\r\n0\r\n\r\n")
            status = s.recv(100).split(b"\r\n")[0]
        self.assertIn(b"411", status)


class TestFollow(unittest.TestCase):
    def test_append_partial_line_and_truncate(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            path = Path(d) / "s.jsonl"
            path.write_bytes(b'{"n":1}\n')
            q = queue.Queue()
            start(file_reader, str(path), q, [0], True)
            self.assertEqual(take(q, 1)[0][1], {"n": 1})

            def append(data: bytes):
                with open(path, "ab") as f:
                    f.write(data)

            append(b'{"n":2}\n{"n":')
            self.assertEqual(take(q, 1)[0][1], {"n": 2})
            time.sleep(0.3)
            self.assertTrue(q.empty(), "a half-written line must not be emitted")
            append(b'3}\n')
            self.assertEqual(take(q, 1)[0][1], {"n": 3})
            path.write_bytes(b'{"n":4}\n')          # truncated / rotated
            self.assertEqual(take(q, 1)[0][1], {"n": 4})


class TestOpenPipe(unittest.TestCase):
    def test_alert_appears_while_the_pipe_is_still_open(self):
        base = {"host": "a", "type": "auth", "user": "u", "src_ip": "203.0.113.5"}
        events = [{**base, "id": i, "ts": 1000 + i, "outcome": "failure"} for i in range(6)]
        events.append({**base, "id": 99, "ts": 1020, "outcome": "success"})
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            p = subprocess.Popen([sys.executable, "-m", "hids_agent.agent", "--out", d, "-q"],
                                 stdin=subprocess.PIPE, text=True, cwd=ROOT,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                p.stdin.write("".join(json.dumps(e) + "\n" for e in events))
                p.stdin.flush()
                feed, end, seen = Path(d) / "alerts.jsonl", time.time() + 15, False
                while time.time() < end and not seen:
                    seen = feed.exists() and '"bruteforce"' in feed.read_text(encoding="utf-8")
                    time.sleep(0.2)
                self.assertTrue(seen, "no live alert while stdin was open")
                self.assertIsNone(p.poll())
            finally:
                p.stdin.close()
                p.wait(timeout=15)


if __name__ == "__main__":
    unittest.main()
