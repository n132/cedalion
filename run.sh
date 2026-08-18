#!/bin/sh
# Build the data, build the site, then serve it.
#
# bugs.json is gitignored, so a fresh clone has no data at all. This is the
# entry point that makes that work: extract.py rebuilds the file from the
# triage database (read-only), build.py assembles docs/ from it, and only then
# does the server start.
#
# One server, not two. There used to be an app.py that served web/ and
# bugs.json directly, skipping the build -- and it could not serve an artifact,
# so every artifact column read "pending" whether or not the bug was disclosed.
# A page that looked right in it could still be wrong on the site, which is the
# opposite of what a local server is for. preview.py serves what build.py
# produced and answers the /b/ routes the way the Worker does, so what you see
# is what is deployed.
#
# The steps stay separate processes on purpose. Nothing that opens the database
# is still running once the socket is open, so the surface reachable over the
# network is exactly the built directory.
#
# Serving without refreshing first is still just `python3 preview.py`.
set -e
cd "$(dirname "$0")"

# Where extract.py's paths come from. The file is gitignored and names this
# machine's layout, which is exactly what extract.py refuses to carry itself --
# it exits naming the variable if one is missing, so a clone with no .env stops
# here with a readable error rather than serving a stale register.
[ -f .env ] && . ./.env

python3 extract.py
python3 build.py
exec python3 preview.py
