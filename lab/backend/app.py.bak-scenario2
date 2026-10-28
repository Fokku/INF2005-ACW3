#!/usr/bin/env python3
"""
INF2005 ACW3 - untrusted backend fixture (CVE-2026-63686 scenario)

The Apache target reverse-proxies this backend and runs its responses through
the mod_proxy_html / mod_xml2enc filter chain. This fixture exists so the team
can observe that the filter chain is active and reachable (verification), and
so it can be used as the attacker-controlled backend during the exploitation
phase.

It ships ONLY benign responses. The response that declares a charset whose
transcoding partly succeeds then fails - the condition that reaches the
vulnerable code path - is intentionally NOT included here; constructing it is
the exploitation-phase task described in docs/03-exploitation-scaffold.md.

Standard library only, so the backend image is just a slim python base (see
backend/Dockerfile, python:3.12-slim) with no extra packages.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8000

# A small HTML document with an absolute link, so that when mod_proxy_html is
# active the proxied copy served under /proxy/ shows rewritten links - an easy
# visual confirmation that the filter chain (and therefore xml2enc) engaged.
SAMPLE_HTML = (
    "<!doctype html>\n<html><head><title>backend</title></head>\n"
    "<body><h1>ACW3 backend</h1>"
    "<p>Proxied through mod_proxy_html + mod_xml2enc.</p>"
    '<a href="http://backend:8000/page2">next page</a>'
    "</body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    server_version = "ACW3Backend/1.0"

    def _send(self, body: bytes, content_type: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._send(b"ok\n", "text/plain; charset=utf-8")
            return

        # /scenario lets the team vary the DECLARED charset during exploitation
        # development (e.g. ?charset=utf-8). The body stays a fixed benign
        # document; only the Content-Type header changes. No crash payload is
        # built in - that construction is the exploitation-phase task.
        if path == "/scenario":
            qs = parse_qs(parsed.query)
            charset = qs.get("charset", ["utf-8"])[0]
            charset = "".join(
                c for c in charset if c.isalnum() or c in "-_."
            )[:40] or "utf-8"

            if qs.get("mode", ["benign"])[0] == "partial-fail":
                # ASCII/Windows-1252-compatible prefix converts first.
                # 0x81 is invalid in glibc's WINDOWS-1252 to UTF-8 conversion.
                body = (
                    b"<!doctype html><html><head><title>ACW3</title></head>"
                    b"<body><h1>ACW3 backend</h1><p>valid converted prefix</p>"
                    b"\x81"
                    b"</body></html>\n"
                )
            else:
                body = SAMPLE_HTML.encode("utf-8")

            self._send(body, f"text/html; charset={charset}")
            return

        self._send(SAMPLE_HTML.encode("utf-8"), "text/html; charset=utf-8")

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        sys.stderr.write("[backend] " + (fmt % args) + "\n")


if __name__ == "__main__":
    print(f"[backend] listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
