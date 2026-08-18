#!/bin/sh
# Build the data, then serve it.
#
# bugs.json is gitignored, so a fresh clone has no data at all. This is the
# entry point that makes that work: extract.py rebuilds the file from
# the triage database (read-only) and only then does the server start.
#
# The two stay separate processes on purpose. app.py never opens the database
# and never shells out, so the surface reachable over the network stays exactly
# one JSON document — running the extractor here, before the socket is open,
# keeps that true.
#
# Serving without refreshing first is still just `python3 app.py`.
set -e
cd "$(dirname "$0")"

# Where extract.py's paths come from. The file is gitignored and names this
# machine's layout, which is exactly what extract.py refuses to carry itself --
# it exits naming the variable if one is missing, so a clone with no .env stops
# here with a readable error rather than serving a stale register.
[ -f .env ] && . ./.env

python3 extract.py
exec python3 app.py
