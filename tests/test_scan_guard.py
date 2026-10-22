"""SSRF checklist tests for the phpatchscan fetcher.

Every target from the public SSRF review checklist (2026-10-22)
is a named case here. Tests are hermetic: the resolver and the
HTTP connections are stubbed, so no test touches the network.
Run: python3 -m unittest discover -s tests
"""

import gzip
import socket
import unittest
from unittest import mock

from phppatchscan import scan, versioning

PUBLIC = "93.184.216.34"
META = "169.254.169.254"
LOOP = "127.0.0.1"


def gai_map(mapping):
    def _gai(host, port, *a, **k):
        if host not in mapping:
            raise socket.gaierror(f"no stub answer for {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (mapping[host], 0))]
    return _gai


def gai_smart(host, port, *a, **k):
    """Literal IPs answer as themselves; known names map; the
    rest fail DNS (as a resolver disagreement would surface)."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 0))]
    except ValueError:
        pass
    table = {"localhost": LOOP, "localhost.": LOOP,
             "metadata.google.internal": META,
             "example.com": PUBLIC,
             "127.0.0.1.nip.io": LOOP, "localtest.me": LOOP}
    if host in table:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (table[host], 0))]
    raise socket.gaierror(f"no stub answer for {host}")


class FakeResp:
    def __init__(self, status=200, headers=(), chunks=(b"ok",)):
        self.status = status
        self._headers = list(headers)
        self._chunks = list(chunks)

    def getheaders(self):
        return list(self._headers)

    def read(self, n=-1):
        if not self._chunks:
            return b""
        c = self._chunks.pop(0)
        if n is not None and n >= 0 and len(c) > n:
            self._chunks.insert(0, c[n:])
            return c[:n]
        return c


class FakeConn:
    instances = []
    responder = staticmethod(lambda conn: FakeResp())

    def __init__(self, host, port, timeout=None, **kw):
        self.host, self.port = host, port
        FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.req = (method, path)

    def getresponse(self):
        return FakeConn.responder(self)

    def close(self):
        pass


class FakePinned(FakeConn):
    def __init__(self, ip, port, sni_host, timeout):
        super().__init__(ip, port, timeout=timeout)
        self.sni_host = sni_host


class LiteralRefusals(unittest.TestCase):
    URLS = [
        "http://127.0.0.1/", "http://localhost/", "http://localhost./",
        "http://127.1/", "http://2130706433/", "http://0x7f000001/",
        "http://017700000001/", "http://0/", "http://[::1]/",
        "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/",
        "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.1.1/",
        "http://100.64.0.1/", "http://169.254.169.254/",
        "http://[fd00:ec2::254]/", "http://metadata.google.internal/",
    ]

    def test_every_spelling_refused(self):
        for url in self.URLS:
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertFalse(r["ok"], url)
            self.assertTrue(r["error"], url)


class ParserTricks(unittest.TestCase):
    def test_tricks_refused(self):
        urls = ["http://example.com\\@127.0.0.1/",
                "http://127.0.0.1#@example.com/",
                "http://user:pass@example.com/",
                "http://example.com:8080/",
                "ftp://example.com/", "file:///etc/passwd",
                "gopher://example.com/"]
        for url in urls:
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(url)
            self.assertFalse(r["ok"], url)
            self.assertTrue(r["error"], url)


class ResolvingNames(unittest.TestCase):
    def test_names_resolving_private_refused(self):
        for host in ("127.0.0.1.nip.io", "localtest.me"):
            with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
                r = scan._fetch(f"http://{host}/")
            self.assertFalse(r["ok"], host)

    def test_public_name_passes(self):
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart):
            self.assertEqual(scan._public_ips("example.com"), [PUBLIC])


class Redirects(unittest.TestCase):
    def setUp(self):
        FakeConn.instances = []

    def _run(self, responder, url="http://example.com/"):
        FakeConn.responder = staticmethod(responder)
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            return scan._fetch(url)

    def test_redirect_to_metadata_refused_before_connect(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://169.254.169.254/")]))
        self.assertFalse(r["ok"])
        self.assertIn("non-public", r["error"])
        self.assertEqual(len(FakeConn.instances), 1)

    def test_redirect_loop_stops(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://example.com/")]))
        self.assertFalse(r["ok"])
        self.assertIn("too many redirects", r["error"])

    def test_redirect_to_file_scheme_refused(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "file:///etc/passwd")]))
        self.assertFalse(r["ok"])
        self.assertIn("http/https", r["error"])

    def test_redirect_to_bad_port_refused(self):
        r = self._run(lambda c: FakeResp(
            302, [("Location", "http://example.com:8080/")]))
        self.assertFalse(r["ok"])
        self.assertIn("80 and 443", r["error"])


class RebindingAndPinning(unittest.TestCase):
    def test_rebinding_second_answer_never_used(self):
        calls = []

        def flip(host, port, *a, **k):
            calls.append(host)
            ip = PUBLIC if len(calls) == 1 else LOOP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

        FakeConn.instances = []
        FakeConn.responder = staticmethod(lambda c: FakeResp(200))
        with mock.patch.object(scan.socket, "getaddrinfo", flip), \
                mock.patch.object(scan.http.client, "HTTPConnection",
                                  FakeConn):
            r = scan._fetch("http://example.com/")
        self.assertTrue(r["ok"])
        self.assertEqual(FakeConn.instances[0].host, PUBLIC)

    def test_https_pins_ip_and_checks_cert_against_hostname(self):
        seen = {}

        class Rec(FakePinned):
            def __init__(self, ip, port, sni_host, timeout):
                super().__init__(ip, port, sni_host, timeout)
                seen.update(ip=ip, sni=sni_host)

        FakePinned.responder = staticmethod(lambda c: FakeResp(200))
        with mock.patch.object(scan.socket, "getaddrinfo", gai_smart), \
                mock.patch.object(scan, "_PinnedHTTPS", Rec):
            r = scan._fetch("https://example.com/")
        self.assertTrue(r["ok"])
        self.assertEqual(seen, {"ip": PUBLIC, "sni": "example.com"})


class ResourceCaps(unittest.TestCase):
    def test_body_capped(self):
        big = FakeResp(200, chunks=[b"A" * (scan._MAX_BODY + 5000)])
        self.assertEqual(len(scan._read_capped(big)), scan._MAX_BODY)

    def test_gzip_never_expanded(self):
        bomb = gzip.compress(b"A" * 200000)
        resp = FakeResp(200, [("Content-Encoding", "gzip")], [bomb])
        raw = scan._read_capped(resp)
        self.assertLessEqual(len(raw), scan._MAX_BODY)
        self.assertNotEqual(raw, b"A" * 200000)

    def test_total_deadline_stops_slow_drip(self):
        class Drip:
            def read(self, n=-1):
                return b"x"

        with mock.patch.object(scan, "_DEADLINE", -1):
            self.assertEqual(scan._read_capped(Drip()), b"")


class DistroWording(unittest.TestCase):
    def test_distro_detection(self):
        self.assertTrue(versioning.distro_build("8.3.6-0ubuntu0.24.04.3"))
        self.assertTrue(versioning.distro_build("8.2.20-1~deb12u1"))
        self.assertFalse(versioning.distro_build("8.3.36"))
        self.assertFalse(versioning.distro_build(None))

    def test_distro_verdict_is_check_not_proof(self):
        v = versioning.verdict_for((8, 3, 6), distro=True)
        self.assertEqual(v["status"], "vulnerable")
        self.assertIn("check signal, not proof", v["detail"])

    def test_patched_is_not_a_general_guarantee(self):
        v = versioning.verdict_for((8, 3, 36))
        self.assertEqual(v["status"], "patched")
        self.assertIn("not a general security guarantee", v["detail"])


if __name__ == "__main__":
    unittest.main()
