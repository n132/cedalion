#!/usr/bin/env python3
"""Serve docs/ locally, including the /b/<id> routes the Pages Function owns.

Local preview only. wrangler runs the real function but needs Node 22; this
covers the same routes so the register, a bug's artifact page and a download
can be checked without it.

It deliberately mirrors functions/b/[id]/[[path]].js rather than sharing code
with it, so treat that file as the authority: if the two ever disagree, the
deployed behaviour is whatever the Function says.

    python3 preview.py            # http://127.0.0.1:60002
"""

import http.server
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "docs")
PORT = int(os.environ.get("PORT", "60002"))
# 0.0.0.0 so it is reachable from another machine. It serves docs/ only,
# which holds nothing that publish.py has not already disclosed.
HOST = os.environ.get("HOST", "0.0.0.0")
CONTACT = "co@bugs.sh"
BUG_PATH = re.compile(r"^/b/([0-9a-f]{8,64})(?:/(.+))?$")


def index():
    try:
        with open(os.path.join(DOCS, "artifacts.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


class Handler(http.server.SimpleHTTPRequestHandler):
    # An artifact with no extension -- `config` -- is guessed as a binary
    # stream and offered as a download. These are text, and worth reading in
    # place.
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      "": "text/plain; charset=utf-8"}

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=DOCS, **kw)

    def send_body(self, body, status=200, ctype="text/html; charset=utf-8"):
        blob = body.encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def bug_page(self, bug_id, entry):
        """The page is the report. Content changes belong in the generator."""
        has = (bool(entry) and not entry.get("embargoed")
               and "report.eml" in entry.get("files", {}))
        body = (f"<div id='report' data-src='/b/{bug_id}/report.eml'>loading…"
                f"</div><script src='/bugpage.js'></script>") if has else (
               "<p class='none'>The report for this bug is not public yet.</p>")
        self.send_body(
            f"<!doctype html><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{bug_id} — cedalion</title>"
            f"<link rel='stylesheet' href='/style.css'>"
            f"<link rel='icon' href='/favicon.svg'>"
            f"<body class='bug'>"
            f"<main class='bugpage'>"
            f"<p><a href='/#vulnerable'>&larr; register</a></p>"
            f"{body}</main>",
            200 if has else 404)

    def do_GET(self):
        m = BUG_PATH.match(self.path.split("?")[0])
        if not m:
            return super().do_GET()

        bug_id, name = m.group(1), m.group(2)
        entry = index().get(bug_id)

        if not name:
            return self.bug_page(bug_id, entry)
        if not entry:
            return self.send_body(
                f"No artifacts published for {bug_id} yet.\n"
                f"Request them from {CONTACT}, quoting the bug id.\n",
                404, "text/plain; charset=utf-8")
        if entry.get("embargoed"):
            return self.send_body(
                f"Artifacts for {bug_id} are under embargo.\n", 403,
                "text/plain; charset=utf-8")
        files = entry.get("files", {})
        # Named with no key: the artifact exists and is deliberately not
        # disclosed yet. Distinct from a name that is absent, which is "no such
        # artifact" -- this one says the file is real and the answer is "not
        # yet", so nobody has to guess whether it is worth asking for.
        if name in files and not files[name]:
            return self.send_body(
                f'"{name}" for {bug_id} is not public yet.\n'
                f"Request it from {CONTACT}, quoting the bug id.\n",
                403, "text/plain; charset=utf-8")
        key = files.get(name)
        if not key:
            have = ", ".join(sorted(files)) or "none"
            return self.send_body(
                f'No artifact "{name}" for {bug_id}. Available: {have}\n',
                404, "text/plain; charset=utf-8")

        self.path = f"/a/{key}"
        return super().do_GET()

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


if not os.path.isdir(DOCS):
    sys.exit("no docs/ — run `python3 build.py` first")

# Threaded, and not for throughput: a browser opens several connections and
# holds them open, and a single-threaded server serves one at a time, so an
# idle-but-open connection stalls every other request until it times out.
# That reads as a page that takes ten seconds to load while curl is instant.
class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


Handler.protocol_version = "HTTP/1.1"      # keep-alive; safe now it threads

with Server((HOST, PORT), Handler) as httpd:
    import socket
    lan = socket.gethostbyname(socket.gethostname())
    print(f"preview on {HOST}:{PORT}   (ctrl-c to stop)")
    print(f"  register      http://{lan}:{PORT}/#vulnerable")
    print(f"  a bug's page  http://{lan}:{PORT}/b/4638111fe2a12980")
    httpd.serve_forever()
