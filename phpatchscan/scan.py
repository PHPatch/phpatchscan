"""Step 1a — external scan (no credentials).

Fingerprints PHP from what a site discloses over HTTP: X-Powered-By /
Server headers, PHPSESSID cookies, CMS generator signals, and exposed
phpinfo pages. An exact version, when disclosed, is checked against the
patched-release floors.

Honest limit: most well-run sites suppress version headers. For those the
scan reports "PHP detected, version hidden — patch status cannot be
confirmed from outside" and recommends the credentialed deep check.
"""

import http.client
import ipaddress
import re
import socket
import ssl
import urllib.parse

from . import versioning

_UA = ("phpatchscan/1.0 (+https://phpatch.com/security; "
       "free vulnerability scan)")
_TIMEOUT = 12
_MAX_BODY = 512 * 1024
_MAX_REDIRECTS = 5
_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php-info.php", "/test.php")


class BlockedTarget(Exception):
    """Target refused by the scanner's SSRF/abuse policy."""


def _public_ips(host):
    """Resolve a host and require EVERY answer to be a public IP.

    Blocks loopback, private, link-local (incl. cloud metadata
    169.254.169.254), reserved, multicast and unspecified addresses,
    so the public scanner can never be pointed at internal services.
    """
    try:
        infos = socket.getaddrinfo(host, None,
                                     proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedTarget(f"DNS lookup failed for {host}: {e}")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # Unwrap transition forms: the real TCP destination of an
        # IPv4-mapped (::ffff:a.b.c.d) or 6to4 (2002:xxxx::) address
        # is the embedded IPv4, so THAT is what must be checked —
        # the IPv6 spelling alone does not trip the IPv4 ranges.
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            elif ip.sixtofour is not None:
                ip = ip.sixtofour
        if ip.is_loopback or ip.is_private or ip.is_link_local or \
                ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise BlockedTarget(
                f"{host} resolves to a non-public address ({ip}); "
                "the scanner only fetches public websites")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise BlockedTarget(f"DNS lookup returned nothing for {host}")
    return ips


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a pinned IP, with SNI + certificate checks against
    the original hostname (defeats DNS-rebinding between the policy
    check and the connect)."""

    def __init__(self, ip, port, sni_host, timeout):
        super().__init__(ip, port, timeout=timeout,
                         context=ssl.create_default_context())
        self._sni_host = sni_host

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._sni_host)


def _literal_refusal(host):
    """Refuse non-standard IP encodings: decimal (2130706433), hex
    (0x7f000001), octal parts (0177.0.0.1), short forms (127.1).
    Resolver libraries disagree on these spellings, so they never
    reach a resolver at all."""
    if "0x" in host.lower():
        return "hex-encoded IP addresses are refused"
    if re.fullmatch(r"[0-9.]+", host):
        parts = host.split(".")
        if len(parts) != 4 or any(
                not p.isdigit() or int(p) > 255 or
                (len(p) > 1 and p.startswith("0")) for p in parts):
            return "non-standard IP address forms are refused"
    return None


def _preflight(url):
    """Validate one fetch target. Called for the initial URL and
    for EVERY redirect hop, so a redirect cannot smuggle in a
    blocked scheme, port, credential or encoded address.
    Returns (error, parts, port); error is None when clean."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "only http/https URLs are scanned", None, None
    if parts.username or parts.password:
        return "URLs with credentials are refused", None, None
    host = parts.hostname
    if not host:
        return "URL has no host", None, None
    refusal = _literal_refusal(host)
    if refusal:
        return refusal, None, None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = -1
    if port not in (80, 443):
        return "only ports 80 and 443 are scanned", None, None
    return None, parts, port


def _fetch(url, ctx=None):
    """Guarded fetch: http/https only, ports 80/443 only, no URL
    credentials, every redirect hop re-validated and IP-pinned,
    body capped. Returns the same dict shape as before."""
    current = url
    for _hop in range(_MAX_REDIRECTS + 1):
        err, parts, port = _preflight(current)
        if err:
            return {"ok": False, "status": None, "final_url": current,
                    "headers": {}, "body": "", "error": err}
        host = parts.hostname
        try:
            ips = _public_ips(host)
        except BlockedTarget as e:
            return {"ok": False, "status": None, "final_url": current,
                    "headers": {}, "body": "", "error": str(e)}
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        host_hdr = host if port in (80, 443) and \
            parts.port is None else f"{host}:{port}"
        conn = None
        try:
            if parts.scheme == "https":
                conn = _PinnedHTTPS(ips[0], port, host, _TIMEOUT)
            else:
                conn = http.client.HTTPConnection(ips[0], port,
                                                  timeout=_TIMEOUT)
            conn.request("GET", path,
                         headers={"User-Agent": _UA, "Host": host_hdr,
                                  "Accept": "*/*",
                                  "Connection": "close"})
            resp = conn.getresponse()
            status = resp.status
            headers = dict(resp.getheaders())
            location = None
            for k, v in headers.items():
                if k.lower() == "location":
                    location = v
            if status in (301, 302, 303, 307, 308) and location:
                conn.close()
                current = urllib.parse.urljoin(current, location)
                continue
            try:
                raw = resp.read(_MAX_BODY + 1)[:_MAX_BODY]
            except http.client.IncompleteRead as e:
                # Server/proxy closed mid-body (common behind CDNs);
                # the partial body is still a successful fetch.
                raw = (e.partial or b"")[:_MAX_BODY]
            body = raw.decode("utf-8", "replace")
            return {"ok": status < 400, "status": status,
                    "final_url": current, "headers": headers,
                    "body": body,
                    "error": None if status < 400 else f"HTTP {status}"}
        except Exception as e:  # DNS, TLS, timeout, refused
            return {"ok": False, "status": None, "final_url": current,
                    "headers": {}, "body": "", "error": str(e)}
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    return {"ok": False, "status": None, "final_url": current,
            "headers": {}, "body": "",
            "error": f"too many redirects (>{_MAX_REDIRECTS})"}


def _h(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def scan(url):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    home = _fetch(url)
    result = {"target": url, "reachable": home["ok"],
              "http_status": home["status"], "final_url": home["final_url"],
              "error": home.get("error"), "signals": {},
              "php_version": None, "version_source": None,
              "cms": [], "phpinfo_exposed": False, "verdict": None}
    if not home["ok"] and home["status"] is None:
        result["verdict"] = {"status": "unreachable",
                             "detail": f"Site did not answer: "
                                       f"{home.get('error')}"}
        return result

    headers, body = home["headers"], home["body"]
    xpb = _h(headers, "X-Powered-By")
    server = _h(headers, "Server")
    cookies = _h(headers, "Set-Cookie")
    gen = _h(headers, "X-Generator")
    if xpb:
        result["signals"]["x_powered_by"] = xpb
    if server:
        result["signals"]["server"] = server
    if "PHPSESSID" in cookies:
        result["signals"]["phpsessid_cookie"] = True
    if gen:
        result["signals"]["x_generator"] = gen

    # CMS fingerprints
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+'
                  r'content=["\']([^"\']+)', body, re.I)
    meta_gen = m.group(1) if m else ""
    low = body.lower()
    if "wp-content" in low or "wp-includes" in low or \
            "wordpress" in meta_gen.lower():
        result["cms"].append("WordPress")
    if "powered by phpbb" in low or "styles/prosilver" in low:
        result["cms"].append("phpBB")
    if "joomla" in meta_gen.lower() or "/media/jui/" in low:
        result["cms"].append("Joomla")
    if "drupal" in gen.lower() or "/core/modules/" in low:
        result["cms"].append("Drupal")
    if meta_gen:
        result["signals"]["meta_generator"] = meta_gen

    # Exact version disclosure: headers first
    for src, text in (("X-Powered-By", xpb), ("Server", server)):
        v = versioning.parse_version(re.search(r"PHP/(\S+)", text).group(1)) \
            if re.search(r"PHP/(\S+)", text) else None
        if v:
            result["php_version"] = versioning.fmt(v)
            result["version_source"] = src
            break

    # phpinfo probes — an exposed phpinfo both leaks the exact version
    # and is itself a finding.
    base = home["final_url"].rstrip("/")
    if result["php_version"] is None or True:
        for path in _PHPINFO_PATHS:
            probe = _fetch(base + path)
            b = probe["body"]
            if probe["status"] == 200 and "phpinfo()" in b and \
                    re.search(r"PHP Version\s*&?#?\w*\s*([0-9]+\.[0-9]+\.[0-9]+)", b):
                vm = re.search(r"PHP Version[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", b)
                result["phpinfo_exposed"] = True
                result["signals"]["phpinfo_path"] = path
                if vm and result["php_version"] is None:
                    result["php_version"] = vm.group(1)
                    result["version_source"] = f"phpinfo ({path})"
                break

    vtuple = versioning.parse_version(result["php_version"])
    if vtuple:
        result["verdict"] = versioning.verdict_for(vtuple)
    elif result["signals"] or result["cms"]:
        result["verdict"] = {
            "status": "indeterminate",
            "detail": "PHP is present (fingerprinted) but the version is "
                      "not disclosed, so the patch status cannot be "
                      "confirmed from outside. Run the deep check (SSH, "
                      "read-only) for a definitive verdict."}
    else:
        result["verdict"] = {
            "status": "no_php_detected",
            "detail": "No PHP signals found. The site may not run PHP, or "
                      "may hide every fingerprint."}
    return result


def render_text(r):
    lines = [f"Target:      {r['target']}",
             f"Reachable:   {r['reachable']} (HTTP {r['http_status']})",
             f"Final URL:   {r['final_url']}"]
    if r["cms"]:
        lines.append(f"CMS:         {', '.join(r['cms'])}")
    if r["php_version"]:
        lines.append(f"PHP version: {r['php_version']} "
                     f"(via {r['version_source']})")
    if r["phpinfo_exposed"]:
        lines.append("!! phpinfo page is publicly exposed — remove it.")
    v = r["verdict"]
    lines.append(f"VERDICT:     {v['status'].upper()}")
    lines.append(f"             {v['detail']}")
    if v["status"] == "indeterminate":
        lines.append("NEXT:        Most well-run sites hide their PHP "
                     "version, so an outside scan cannot be certain. "
                     "For a certain answer, run the read-only deep "
                     "check on the server (it only reads versions and "
                     "changes nothing):")
        lines.append("               phppatch deepcheck --host "
                     "root@your-server")
        lines.append("             Site ownership is verified before "
                     "any deeper check. This scan used passive fingerprinting and limited, read-only path checks only — no exploit probes.")
    return "\n".join(lines)
