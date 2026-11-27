"""Exercise the replay workspace over its normal loopback interface."""

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dashboard.server import Cases


class DashboardTests(unittest.TestCase):
    def test_replay_appears_in_library_and_has_downloads(self):
        with TemporaryDirectory() as folder, ThreadingHTTPServer(("127.0.0.1", 0), Cases) as server:
            server.output = Path(folder).resolve()
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                origin = f"http://127.0.0.1:{server.server_port}"
                with urlopen(origin + "/cases", timeout=5) as response:
                    self.assertIn("No replays here yet", response.read().decode())
                request = Request(origin + "/run", data=b'{"split":"dev","mode":"prevent"}',
                                  headers={"Content-Type": "application/json", "Origin": origin})
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 201)
                    url = json.load(response)["url"]
                with urlopen(origin + "/cases", timeout=5) as response:
                    self.assertIn(f'href="{url}"', response.read().decode())
                with urlopen(origin + url, timeout=5) as response:
                    case = response.read().decode()
                    self.assertIn('id="host"', case)
                    self.assertIn("Synthetic dev", case)
                    self.assertIn("100.0%", case)
                with urlopen(origin + url + "/files/report.md", timeout=5) as response:
                    self.assertIn("attachment", response.headers["Content-Disposition"])
                    self.assertIn("PASS", response.read().decode())
                with self.assertRaises(HTTPError) as caught:
                    urlopen(origin + url + "/files/config_used.json", timeout=5)
                self.assertEqual(caught.exception.code, 404)
                (server.output / url.rsplit("/", 1)[1] / "dashboard.html").write_text("old export", encoding="utf-8")
                with urlopen(origin + url, timeout=5) as response:
                    self.assertIn("Replay findings", response.read().decode())
            finally:
                server.shutdown()
                thread.join()
