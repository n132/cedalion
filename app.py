#!/usr/bin/env python3
"""Cedalion — a read-only listing of the kernel bugs found so far.

Serves the page, its logo and bugs.json on port 60001, and nothing else. Of
those, bugs.json is the only one carrying data. This process never opens
the triage database, never reads a bug's artifacts, and never shells out:
the only file it touches is the extracted bugs.json beside it. Producing that
file is extract.py's job, run separately.

Keeping the two apart means the surface reachable over the network is exactly
one JSON document. An in-page refresh button would have handed a network caller
the ability to spawn a process and to reach the database indirectly, which is a
poor trade for saving a shell command.

    python3 extract.py        # refresh the data
    python3 app.py            # http://<host>:60001
"""
from __future__ import annotations

import json
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response

HERE = os.path.dirname(os.path.abspath(__file__))
# Data at the root, front-end under web/. bugs.json is the one file that is
# generated rather than written by hand, and the one file that is gitignored,
# so it sits apart from the source it feeds.
#
# Where it lives is a parameter, because this server needs nothing else from
# the machine it runs on: no claudes.db, no lore mirror, no CVE corpus, no
# kernel clone. Those belong to extract.py. Hand this process a bugs.json from
# anywhere and app.py plus web/ is the whole site.
DATA = os.environ.get("CEDALION_DATA", os.path.join(HERE, "bugs.json"))
WEB = os.path.join(HERE, "web")

# Every asset this server will ever hand out, named here rather than resolved
# from the request. A route picks one of these constants, so no path a caller
# sends can reach a file that is not on this list.
PAGE_FILE = os.path.join(WEB, "index.html")
LOGO_FILE = os.path.join(WEB, "logo.svg")
LOGO_LIGHT_FILE = os.path.join(WEB, "logo-light.svg")
FAVICON_FILE = os.path.join(WEB, "favicon.svg")
CSS_FILE = os.path.join(WEB, "style.css")
JS_FILE = os.path.join(WEB, "cedalion.js")
PORT = int(os.environ.get("CEDALION_PORT", "60001"))
HOST = os.environ.get("CEDALION_HOST", "0.0.0.0")

app = FastAPI(title="Cedalion")


def load() -> dict:
    try:
        with open(DATA) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"generated_at": "never", "counts": {}, "bugs": []}


@app.get("/api/bugs")
async def api_bugs():
    return JSONResponse(load())


# The same document under the name a static host would give it. The page asks
# for `bugs.json` relative to itself so that one index.html works both here and
# on a plain file host, where there is no server to answer /api/bugs. Two names,
# one document, no second copy of the data.
@app.get("/bugs.json")
async def bugs_json():
    return JSONResponse(load())


def _asset(path: str, media_type: str) -> Response:
    """Serve one of the fixed files above, read from disk on every request so
    editing a page or the stylesheet shows up on reload without a restart.

    no-store because the previous behaviour half-defeated that: the responses
    carried no cache headers at all, so a browser was free to keep serving its
    own copy and an edit to the CSS would not appear until a hard reload. There
    is nothing to gain by caching a file this server re-reads anyway.
    """
    try:
        with open(path, "rb") as f:
            return Response(f.read(), media_type=media_type,
                            headers={"Cache-Control": "no-store"})
    except OSError:
        return Response(status_code=404)


@app.get("/logo.svg")
async def logo():
    """The mark on a black plate. The pages use the light twin below; this one
    is kept for anywhere dark."""
    return _asset(LOGO_FILE, "image/svg+xml")


@app.get("/logo-light.svg")
async def logo_light():
    return _asset(LOGO_LIGHT_FILE, "image/svg+xml")


@app.get("/favicon.svg")
async def favicon():
    """Tab icon: cropped to the ink, no plate, follows the browser's theme."""
    return _asset(FAVICON_FILE, "image/svg+xml")


@app.get("/style.css")
async def style():
    return _asset(CSS_FILE, "text/css")


@app.get("/cedalion.js")
async def script():
    return _asset(JS_FILE, "application/javascript")


@app.get("/", response_class=HTMLResponse)
async def index():
    """The issues list — the register itself, and the only page there is."""
    return _asset(PAGE_FILE, "text/html; charset=utf-8")


if __name__ == "__main__":
    import sys
    import uvicorn
    # A path on the command line beats the environment, which beats the file
    # beside this one. Printed rather than assumed: serving yesterday's blob
    # from the default path looks exactly like serving today's.
    if len(sys.argv) > 1:
        DATA = os.path.abspath(sys.argv[1])
    print(f"serving {DATA}"
          f"{'' if os.path.isfile(DATA) else '  (missing — the page will be empty)'}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
