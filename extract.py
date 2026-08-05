#!/usr/bin/env python3
"""Extract the Cedalion bug list from claudeManager's data. READ-ONLY.

This script never writes to claudes.db and never touches a bug's artifacts —
it opens the database with mode=ro and only ever reads report.md files. Its one
output is bugs.json next to this file. It reads three other things, all of them
local and all of them read-only: the kernel CVE corpus for a base score, the
stable clone for a fixing commit's subject, and the lore mirror for the postings
behind the Processing rows.

Per bug it produces:

  bug_id  the bug's hash_id, the identifier bugs are referred to by
  hash    sha256 of the report.md bytes, i.e. a fingerprint of the report's
          exact content (NOT the same thing as hash_id, which identifies the
          bug rather than the text of its report)
  view    vulnerable | processing | patched — which tab it belongs to

Each view emits only its own columns; see the README.

Dismissed, Dup and manually-entered bugs are left out. So are scooped ones —
somebody upstream fixed the same defect first — which are counted instead:
the fix is not ours and neither is any CVE on it.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "bugs.json")

DB = os.environ.get("CEDALION_DB", "/home/n132/KFC/claudeManager/claudes.db")
TRIAGED_DIR = os.environ.get("CEDALION_TRIAGED", "/home/n132/KFC/Triaged")
TRIAGE_DIR = os.environ.get("CEDALION_TRIAGE", os.path.expanduser("~/Triage"))

# Kernel findings only. The database also carries chrome-v8 and chromium rows
# from the same pipeline; this register is about the kernel, so other repos are
# out. Older rows predate the column, hence the COALESCE to the default.
PROJECT_TYPE = "kernel"

EXCLUDED_STATES = ("Dismissed", "Dup")

# A finding is "scooped" when somebody upstream fixed the same defect before we
# got there. The marker lives in the free-text notes ("Scooped", "scooped:
# <commit>"), independently of state: of the 134, 116 were then dismissed.
#
# Dismissed means dismissed — those 116 are excluded with every other dismissed
# row, no exception. The rest are counted but not listed: the fix is not ours
# and neither is any CVE on it, so a row for one has nothing to show.
#
# Two things in the notes are NOT a scoop, and reading them as one was wrong:
#
#   * "Could be Scooped" is a suspicion, not an outcome. Three rows say only
#     that, all of them Reported — they belong in Processing, not dropped.
#   * A row carrying an ASSIGNED CVE is ours whatever the note says. One row
#     (CVE-2026-64048) has both, and dropping it put the register one CVE below
#     the manager's own count.
SCOOPED_NOTE = "%scoop%"
SCOOPED_MAYBE = "%could be scoop%"
SCOOPED_STATE = "Fixed by others"

# Two kinds of row are not findings of this pipeline, and both are identified
# by the shape of their id rather than by any column, because the database has
# no field that says where a bug came from:
#
#   * typed in by hand — a synthetic "manual-" + a 16-hex digest of the
#     description (see the manual-add endpoint in claudeManager);
#   * from syzbot — named by syzbot's own 40-hex sha1.
#
# The pipeline names its own findings with a bare 16-hex digest, so the three
# populations are told apart by id alone. That split is categorical rather than
# statistical, which is what makes it safe to filter on: all 1496 of the 16-char
# rows carry a report, and none of the 224 40-char rows carries one — there is
# no report because the crash was somebody else's to begin with. Two of the
# 40-char rows were already known as anomalies before the source of them was:
# the pair dropped from Patched for having nothing to show are both syzbot.
#
# Neither kind appears in Vulnerable or Processing. Both still contribute a CVE:
# an assigned CVE is this project's output whoever first tripped over the bug,
# and the register would understate itself by 11 without them. The exception is
# gated on the states that land in Patched, whose columns are cve / commit /
# cvss — so such a row contributes its number and nothing else, no foreign id
# and no hand-entered text.
#
# NB: the bugs table also has a `manual` column, and it is NOT the first of
# these — it is set on 1265 of the 1297 in-scope rows, so filtering on it would
# empty the list.
MANUAL_ID_PREFIX = "manual-"
SYZBOT_ID_LEN = 40

# A claimed CVE means the fix is already upstream, so "CVE Claimed" and "Fixed"
# describe the same place on the road. They are tallied as one category, named
# "Fixed" — the outcome rather than the paperwork.
STATE_ALIASES = {"CVE Claimed": "Fixed"}

# The three views on the findings page. A row publishes only which of these it
# is in — never the state name itself. "Exp Available" attached to a specific,
# still-unfixed id would tell a reader a working exploit exists for it, which is
# a different disclosure from "not fixed yet"; the view says only the latter.
VIEW_PATCHED = "patched"          # landed upstream, ours or somebody else's
VIEW_PROCESSING = "processing"    # posted to the list, not merged yet
VIEW_VULNERABLE = "vulnerable"    # still live, nothing sent
_VIEW_BY_STATE = {
    "Fixed": VIEW_PATCHED,
    "CVE Claimed": VIEW_PATCHED,
    # "Reported" is claudeManager's term for sent upstream, which is the same
    # thing as being on lore. There is no separate lore marker in the database
    # to key off, and the local mirror is empty, so this is the signal.
    "Reported": VIEW_PROCESSING,
}


def view_of(state: str) -> str:
    return _VIEW_BY_STATE.get(state or "", VIEW_VULNERABLE)


# The states that land in Patched, derived from the map above rather than
# written out again — the CVE exception below is gated on them, and the two
# must not be able to drift apart.
PATCHED_STATES = tuple(s for s, v in _VIEW_BY_STATE.items() if v == VIEW_PATCHED)


# The kernel CVE corpus, one JSON record per CVE, for the CVSS base score.
CVE_DIR = os.environ.get("CEDALION_CVE_DIR", "/lake/cves/cve/published")

# Notes on a Reported bug hold the subject line the patch was posted under —
# except for a handful that hold a status instead. Those are not subjects.
_STATUS_NOTES = ("patch sent", "patch accepted", "could be scooped", "scooped")


def patch_subject(notes: str | None) -> str:
    """The subject a Reported bug's patch went out under, kept in its notes.

    This is the only thing that can locate the posting: no message-id and no
    lore URL is stored anywhere, so it is also the key the local lore mirror
    below is searched with.
    """
    for line in (notes or "").splitlines():
        line = line.strip()
        low = line.lower()
        if not line or any(low.startswith(s) for s in _STATUS_NOTES):
            continue
        if ": " in line:          # `subsystem: what it fixes`, a kernel subject
            return line
    return ""


# ------------------------------------------------------------------- lore --
#
# The local mirror kept by /lake/lore-fetch/lore.py: each list's public-inbox
# epochs as bare git repos, plus an FTS5 index over the messages in them. Read
# strictly — this never fetches, never syncs and never writes to the mirror.
LORE_DB = os.environ.get("CEDALION_LORE_DB", "/lake/lore/lore.db")

# The addresses this project's patches go out from. Subject alone is not enough
# to identify a posting as ours — it would just as happily match a stranger's
# mail carrying the same title — so a candidate must also come from one of
# these. They are the two authors behind every fixing commit in Patched that we
# wrote ourselves.
PATCH_SENDERS = ("xmei5@asu.edu", "bestswngs@gmail.com")


def strip_patch_tag(subj: str) -> str:
    """`[PATCH net v2 1/2] tipc: fix ...` -> `tipc: fix ...`, the title the
    commit will land under once the patch is applied."""
    return re.sub(r"^\s*\[[^\]]*\]\s*", "", subj or "").strip()


def _norm_subject(subj: str) -> str:
    """A subject cut down to what identifies the patch.

    Drops any `Re:` and the whole bracket tag, so the note's bare
    `tipc: fix ...` and the posting's `[PATCH net v2 1/2] tipc: fix ...` land on
    one key — and so do v1 and v3 of the same patch, which is what lets the
    newest revision win in lore_postings().
    """
    s = re.sub(r"^\s*(?:re|fwd|aw)\s*:\s*", "", subj or "", flags=re.I)
    return re.sub(r"\s+", " ", strip_patch_tag(s)).strip().lower()


def _msg_time(date: str) -> float:
    """Sort key for a message. The mirror stores the Date header verbatim, and
    an RFC-2822 date does not sort as text."""
    try:
        return email.utils.parsedate_to_datetime(date).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


# How much two titles have to agree, measured AFTER the subsystem prefix, before
# they are worth testing as two revisions of one patch.
#
# Measuring the whole title does not work. A kernel subject opens with
# `subsystem: file: `, which is boilerplate two unrelated fixes to the same file
# share for free — `netfilter: nf_conntrack_sip: fix ` is 33 characters of
# agreement between a fix for an OOB read in epaddr_len() and a fix for an
# uninitialised rtp_addr in process_sdp(), which are different bugs. Counting
# only what follows the last `: ` scores that pair 4 and the real revisions
# 20-35, which separates them cleanly.
_REVISION_BODY = 15


def _shared_body(a: str, b: str) -> int:
    """Length of the common prefix of two subjects, ignoring the part of it
    that is only `subsystem: file: ` boilerplate."""
    common = os.path.commonprefix((a, b))
    return len(common.rpartition(": ")[2])


def _touched_files(blob: str, _cache: dict = {}) -> frozenset:
    """The paths a posting's diff touches, off the `diff --git` lines."""
    if blob not in _cache:
        _cache[blob] = frozenset(
            re.findall(r"^diff --git a/(\S+)", lore_patch(blob), re.M))
    return _cache[blob]


def _fold_revisions(best: dict) -> None:
    """Point a retitled earlier revision at the newest one.

    Keying on the subject collapses revisions that kept their title — v1 and v3
    of the same wording land on one key and the newest wins. A patch *reworded*
    between revisions does not: it sits under two keys, and a note carrying the
    earlier wording would link the superseded posting and draw its diff, which
    is the one failure this whole path exists to avoid. Seen in this set:

        tipc: fix use-after-free of discoverer in tipc_disc_rcv()
        tipc: fix use-after-free of the discoverer in tipc_disc_rcv()   (v3)

    Two keys are one patch only when BOTH hold: their titles agree past the
    subsystem prefix, and their diffs touch a file in common. Each test alone
    lets a wrong pair through, and the two failures point opposite ways:

        fs/ntfs3: fix out-of-bounds read in read_log_rec_buf()        (fslog.c)
        fs/ntfs3: fix out-of-bounds read of INDEX_ROOT in reparse…    (fsntfs.c)

    agree on 23 characters of body and are unrelated — the file test rejects
    them. While

        netfilter: nf_conntrack_sip: fix OOB read in epaddr_len …
        netfilter: nf_conntrack_sip: fix use of uninitialized rtp_addr …

    are two different bugs in one file, which the file test cannot tell apart —
    they agree on 4 characters of body, so the title test rejects them.

    The older key is kept rather than deleted, so a note written against the old
    wording still resolves; it just resolves to the revision that superseded it.
    """
    keys = sorted(best)
    for i, one in enumerate(keys):
        for other in keys[i + 1:]:
            if _shared_body(one, other) < _REVISION_BODY:
                continue
            a, b = _touched_files(best[one][3]), _touched_files(best[other][3])
            if not (a and b and a & b):
                continue
            lo, hi = (one, other) if best[one][0] < best[other][0] else (other, one)
            best[lo] = best[hi]


def lore_postings(_cache: dict = {}) -> dict:
    """{normalised subject: (msgid, subject, blob)} for our own postings.

    One query for the whole run rather than one per row: a phrase search over a
    couple of million indexed messages costs seconds each, and every Processing
    row needs an answer. Replies are skipped — a thread is located by the patch
    that opened it — and where a subject was posted more than once the newest
    wins, since the latest revision is the one to send a reader to.
    """
    if _cache:
        return _cache
    _cache["\0"] = None           # only try once, even if the mirror is absent
    if not os.path.exists(LORE_DB):
        return _cache
    match = " OR ".join(f"frm:{a.split('@')[0]}" for a in PATCH_SENDERS)
    try:
        conn = sqlite3.connect(f"file:{LORE_DB}?mode=ro", uri=True)
        rows = conn.execute(
            """SELECT m.msgid, m.date, m.frm, m.subj, m.blob
                 FROM fts f JOIN msgs m USING(msgid)
                WHERE f.fts MATCH ?""", (match,)).fetchall()
        conn.close()
    except sqlite3.Error:
        return _cache
    best: dict = {}
    for msgid, date, frm, subj, blob in rows:
        # `frm:` filters a tokenised column, so it matched the local part of the
        # address and not the address itself. Confirm the whole one before
        # taking the message for ours.
        if not any(a in (frm or "").lower() for a in PATCH_SENDERS):
            continue
        # A patch, not a reply to one: only the mail that carries the diff can
        # answer either of the two things the page wants from it.
        tag = re.match(r"\s*\[([^\]]*)\]", subj or "")
        if not tag or "PATCH" not in tag.group(1).upper():
            continue
        key = _norm_subject(subj)
        if not key:
            continue
        when = _msg_time(date)
        if key not in best or when > best[key][0]:
            best[key] = (when, msgid, subj, blob)
    _fold_revisions(best)
    _cache.update({k: (v[1], v[2], v[3]) for k, v in best.items()})
    return _cache


# How much of a subject has to line up before a prefix counts as evidence. A
# kernel subject is `subsystem: what it fixes`, and the subsystem alone is
# shared by dozens of postings — 30 characters is well past that on every
# subject in this set.
_PREFIX_FLOOR = 30


def resolve_posting(subject: str):
    """The posting a note's subject refers to, or None.

    An exact subject first. Failing that, an *anchored* prefix in either
    direction, which is what recovers a note that does not say quite what the
    mail said:

      * text pasted in after the subject — one note carried a mail client's
        UI chrome ("… U16_MAX entries 收件箱 Linux Kernel/Sent"), and the
        posting's subject is a prefix of it;
      * a note that stops early, where the posting's subject carries on
        ("… in tipc_lxc_xmit()" vs "… in tipc_lxc_xmit() on node up").

    A prefix, never a similarity score. Scoring these subjects was tried and it
    is not safe at any threshold that also recovers anything: at 0.72 it put an
    ext4 row on an ntfs3 patch, and matched `ntfs_read_mft` to a fix for
    `read_log_rec_buf()`. A wrong diff under a row is worse than a dash, so a
    prefix that two different postings both answer to is treated as no answer.
    """
    postings = lore_postings()
    key = _norm_subject(subject)
    if not key:
        return None
    hit = postings.get(key)
    if isinstance(hit, tuple):
        return hit
    if len(key) < _PREFIX_FLOOR:
        return None
    found = [v for k, v in postings.items()
             if isinstance(v, tuple) and len(k) >= _PREFIX_FLOOR
             and (key.startswith(k) or k.startswith(key))]
    return found[0] if len(found) == 1 else None


# git's own trailer: "-- " on a line of its own followed by the version that
# produced the patch. Not part of the diff. The trailing space is what the
# standard says and what git sends, but enough mailers strip it on the way
# through that two postings in the mirror arrive with a bare "--", so both are
# taken. Anchoring at the end of the message and insisting on a version-shaped
# line after it is what keeps this off a removed line that reads "--".
_SIGNATURE = re.compile(r"\n-- ?\n\d[\d.]*\S*\s*\Z")


def lore_patch(blob: str) -> str:
    """The diff exactly as posted, read out of the mirror's git repo.

    public-inbox stores each message as a blob at path `m` in its own commit,
    and the mirror records where: "<repo>::<rev>". Only the diff is taken — the
    commit message and the headers are a click away on lore, and the box on the
    page is for the code.
    """
    repo, _, rev = (blob or "").partition("::")
    if not rev:
        return ""
    try:
        p = subprocess.run(["git", "-C", repo, "cat-file", "-p", f"{rev}:m"],
                           capture_output=True, timeout=30)
        if p.returncode != 0:
            return ""
        msg = email.message_from_bytes(p.stdout, policy=email.policy.default)
        body = msg.get_body(preferencelist=("plain",))
        text = body.get_content() if body else ""
    except (OSError, subprocess.SubprocessError, LookupError, ValueError):
        return ""
    start = text.find("\ndiff --git ")
    if start < 0:
        return ""
    return _SIGNATURE.sub("", text[start + 1:]).rstrip() + "\n"


def cvss_score(cve: str, _cache: dict = {}) -> str:
    """Base score from the published CVE record, read off disk.

    Offline: this reads the local corpus at CVE_DIR, never the network. A CVE
    with no record or no metrics comes back empty and prints as a dash.
    """
    if not cve:
        return ""
    if cve in _cache:
        return _cache[cve]
    score = ""
    try:
        year = cve.split("-")[1]
        with open(os.path.join(CVE_DIR, year, cve + ".json")) as f:
            rec = json.load(f)
        metrics = rec.get("containers", {}).get("cna", {}).get("metrics") or []
        for m in metrics:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                base = (m.get(key) or {}).get("baseScore")
                if base is not None:
                    score = f"{float(base):g}"
                    break
            if score:
                break
    except (OSError, ValueError, TypeError, IndexError, json.JSONDecodeError):
        score = ""
    _cache[cve] = score
    return score


# cgit link to the fixing commit: .../commit/?id=<hash>
_COMMIT_LINK_RE = re.compile(r"id=([0-9a-f]{7,40})", re.IGNORECASE)


def fix_commit_of(link: str | None) -> str:
    m = _COMMIT_LINK_RE.search(link or "")
    return short(m.group(1).lower()) if m else ""


# The local kernel clone the fixing commits are resolved against.
STABLE_REPO = os.path.expanduser(os.environ.get("STABLE_REPO", "~/kernel/stable"))


def commit_title(sha: str, _cache: dict = {}) -> str:
    """Subject line of a fixing commit, read from the local clone.

    Offline: this reads STABLE_REPO, never the network. A commit not in that
    tree comes back empty and prints as a dash. The subject of a merged commit
    is public the moment it lands, so publishing it discloses nothing.
    """
    if not sha:
        return ""
    if sha in _cache:
        return _cache[sha]
    title = ""
    if os.path.isdir(STABLE_REPO):
        try:
            p = subprocess.run(
                ["git", "-C", STABLE_REPO, "log", "-1", "--format=%s", sha],
                capture_output=True, text=True, timeout=30,
            )
            if p.returncode == 0:
                title = p.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            title = ""
    _cache[sha] = title
    return title


def triage_dir_name(hash_id: str) -> str:
    """Directory name used under ~/Triage/ — mirrors claudeManager's rule."""
    if hash_id.startswith("manual-"):
        return hash_id
    return hash_id[:16]


def report_path(hash_id: str) -> str | None:
    """Locate a bug's report.md, preferring Triaged/ like the manager does."""
    candidates = (
        os.path.join(TRIAGED_DIR, hash_id, "report.md"),
        os.path.join(TRIAGE_DIR, triage_dir_name(hash_id), "Results", "report.md"),
    )
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


# Every published identifier is cut to this. 12 hex is the length the kernel
# uses to cite a commit, and it is applied to the bug id and the report hash too
# so the three columns read as one kind of thing. Verified collision-free across
# the current set: 1238 bug ids and 1208 report hashes stay distinct at 12.
ID_LEN = 12


def short(value: str) -> str:
    return (value or "")[:ID_LEN]


# Rank used to pick which member of a link group represents it: the furthest
# along the pipeline wins, since that is the row carrying the real outcome.
_STATE_RANK = {
    "Fixed": 6, "CVE Claimed": 5, "Reported": 4, SCOOPED_STATE: 3,
    "Exp Available": 2, "PoC Available": 1, "Crash Available": 0,
}


def collapse_link_groups(rows):
    """Collapse each link group to a single finding.

    `linked_ids` holds the other hash_ids a bug is linked to — the same defect
    reached more than once. Counting every member separately inflates the list:
    31 groups here, worth 37 extra rows. One row per group is the honest count.

    Returns (representative_rows, merged_away_count). The representative is the
    member furthest along the pipeline, breaking ties on the newest DB id, so a
    group that reached "CVE Claimed" is not represented by its "PoC Available"
    sibling.
    """
    by_hash = {r[1]: r for r in rows}

    # Union the groups transitively: A may name B while C names A.
    parent = {h: h for h in by_hash}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for r in rows:
        hash_id, linked = r[1], r[3]
        for other in (linked or "").split():
            if other in by_hash:          # ignore links to out-of-scope bugs
                union(hash_id, other)

    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(find(r[1]), []).append(r)

    reps = []
    for members in groups.values():
        members.sort(key=lambda r: (_STATE_RANK.get(r[2], -1), r[0]), reverse=True)
        reps.append(members[0])
    reps.sort(key=lambda r: r[0], reverse=True)   # newest first, as before
    return reps, len(rows) - len(reps)


# What each view is allowed to publish, checked rather than trusted before
# anything is written. bugs.json is handed to the browser verbatim by
# /api/bugs, so a field added to the wrong branch is a disclosure the moment it
# lands — and the three branches that build these rows sit sixty lines apart,
# where nothing sees them together. This does.
PUBLISHED = {
    VIEW_VULNERABLE: {"view", "bug_id", "hash"},
    VIEW_PROCESSING: {"view", "bug_id", "title", "lore", "patch"},
    VIEW_PATCHED:    {"view", "cve", "commit", "title", "cvss"},
}

# A Vulnerable row names a live, unfixed bug, so every value on one has to be an
# opaque digest and nothing else: no path, no function, no crash text, no
# description. The other two views describe patches that are already public on
# lore, which is why only this one is checked for shape as well as for shape's
# absence.
_OPAQUE = re.compile(r"[0-9a-f]{0,%d}" % ID_LEN)


def check_published(bugs: list) -> None:
    """Refuse to write a row carrying more than its view may publish."""
    for b in bugs:
        allowed = PUBLISHED.get(b.get("view"))
        if allowed is None:
            sys.exit(f"refusing to write: unknown view {b.get('view')!r}")
        extra = sorted(set(b) - allowed)
        if extra:
            sys.exit(f"refusing to write: a {b['view']} row carries {extra}, "
                     f"which that view does not publish")
        if b["view"] != VIEW_VULNERABLE:
            continue
        for k, v in b.items():
            if k != "view" and not _OPAQUE.fullmatch(str(v)):
                sys.exit(f"refusing to write: {k} on a Vulnerable row is not an "
                         f"opaque digest ({v!r}) — that view names live bugs")


def collect() -> dict:
    if not os.path.exists(DB):
        sys.exit(f"database not found: {DB}")

    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    placeholders = ",".join("?" for _ in EXCLUDED_STATES)
    patched_states = ",".join("?" for _ in PATCHED_STATES)
    rows = conn.execute(
        f"""SELECT id, hash_id, state, linked_ids,
                   (lower(COALESCE(notes, '')) LIKE ?
                    AND lower(COALESCE(notes, '')) NOT LIKE ?
                    AND trim(COALESCE(cve_number, '')) = '') AS scooped,
                   cve_number, notes, commit_link
            FROM bugs
            WHERE ((hash_id NOT LIKE ? AND length(hash_id) != ?)
                   OR (state IN ({patched_states})
                       AND trim(COALESCE(cve_number, '')) != ''))
              AND COALESCE(project_type, 'kernel') = ?
              AND state NOT IN ({placeholders})
            ORDER BY id DESC""",
        (SCOOPED_NOTE, SCOOPED_MAYBE, MANUAL_ID_PREFIX + "%", SYZBOT_ID_LEN,
         *PATCHED_STATES, PROJECT_TYPE, *EXCLUDED_STATES),
    ).fetchall()

    # Printed rather than published: these are numbers about what is NOT on the
    # register, and an aggregate no page draws is still served to anyone who
    # fetches the JSON. Both halves are printed because the interesting one is
    # the second: a row kept for its CVE alone is the exception working.
    foreign = conn.execute(
        f"""SELECT (hash_id LIKE ?) AS by_hand,
                   trim(COALESCE(cve_number, '')) != '' AS has_cve,
                   COUNT(*)
              FROM bugs
             WHERE (hash_id LIKE ? OR length(hash_id) = ?)
               AND COALESCE(project_type, 'kernel') = ?
               AND state NOT IN ({placeholders})
             GROUP BY 1, 2""",
        (MANUAL_ID_PREFIX + "%", MANUAL_ID_PREFIX + "%", SYZBOT_ID_LEN,
         PROJECT_TYPE, *EXCLUDED_STATES)).fetchall()
    for by_hand, has_cve, n in sorted(foreign):
        kind = "hand-entered" if by_hand else "syzbot"
        why = "kept for its CVE" if has_cve else "left out"
        print(f"  {kind:12} : {n} {why}")

    # Scooped overrides whatever state the row was left in — it is the outcome
    # that actually happened. `notes` itself is never published; it is read here
    # only to classify.
    rows = [(i, h, SCOOPED_STATE if sc else st, li, cv, nt, cl)
            for i, h, st, li, sc, cv, nt, cl in rows]

    conn.close()

    rows, merged = collapse_link_groups(rows)

    bugs = []
    states: dict[str, int] = {}
    missing_report = 0
    scooped = 0
    incomplete = 0
    cves_seen = set()
    postings_seen = set()
    for (_id, hash_id, state, _linked, cve,
         notes, commit_link) in rows:
        # Read for every row, not just the Vulnerable ones that publish the
        # fingerprint: `with a report` counts the whole register, so skipping
        # the others would report them all as missing.
        report_hash = ""
        path = report_path(hash_id)
        if path:
            with open(path, "rb") as f:
                report_hash = hashlib.sha256(f.read()).hexdigest()
        else:
            missing_report += 1

        # Scooped findings are counted, not listed. Somebody upstream fixed the
        # same defect first, so the fix is not ours and neither is any CVE on it
        # — 133 of the 134 carry no CVE number, and listing them under Patched
        # inflated that tab from 88 to 212 with rows that had nothing to show.
        # The count is the honest thing to publish, and it keeps 124 rows out of
        # a document served without authentication.
        if state == SCOOPED_STATE:
            scooped += 1
            continue

        view = view_of(state)
        s = STATE_ALIASES.get(state or "", state or "Unknown")
        states[s] = states.get(s, 0) + 1

        # A row carries EXACTLY the columns its own view draws, and nothing
        # else: bugs.json is handed to the browser verbatim by /api/bugs, so a
        # field is published whether or not the page paints it. That is why the
        # three views emit three different shapes rather than one union — a
        # Vulnerable row must not carry a title, because the title of a patch
        # that has not been sent names a live, unfixed vulnerability.
        #
        # Processing rows may, and that is the whole difference: a Reported bug
        # has already been posted to a public mailing list. Its title, its diff
        # and the file it touches went out with it — three of the four fields
        # below are copied straight back off that posting, so a Processing row
        # is a pointer to public mail rather than a disclosure of its own.
        #
        # The bug's own `description` from the database is no longer read at
        # all. It was written for triage, not for the list, and it said things
        # the patch does not.
        if view == VIEW_VULNERABLE:
            # No date. `first_added_at` is when the row reached claudeManager,
            # not when the bug was found — it moves in scan-sized batches (605
            # rows share one month, 246 share five days), so an age computed
            # from it dated the scan and not the finding. There is no column in
            # the database that dates the finding itself, so rather than publish
            # a number that reads like one and is not, the view shows none.
            bugs.append({
                "view": view,
                "bug_id": short(hash_id),
                "hash": short(report_hash),
            })
        elif view == VIEW_PROCESSING:
            subject = patch_subject(notes)
            posting = resolve_posting(subject)
            # One row per posting, the same way Patched is one row per CVE:
            # several findings can be the same defect reached by different
            # routes, and the patch that fixes them is one patch. `linked_ids`
            # catches most such pairs before this, but not all — two tipc rows
            # arrived under different notes (`tipc_lxc_xmit() on node up` and
            # `tipc_named_node_up() on empty publication list`) and nothing
            # short of the posting they both resolve to shows they are one.
            #
            # Only rows that found a posting can be paired this way. Two that
            # did not are two rows: without the mail there is no evidence they
            # are the same patch, and guessing from the notes is what the whole
            # of resolve_posting() refuses to do.
            if posting:
                if posting[0] in postings_seen:
                    states[s] -= 1        # not listed, so not counted either
                    continue
                postings_seen.add(posting[0])
            bugs.append({
                "view": view,
                # The same identifier a Vulnerable row publishes, so a finding
                # keeps its name as it moves between the tabs and a row here
                # can still be looked up in the manager.
                "bug_id": short(hash_id),
                # The patch's own title, taken from the posting where the
                # mirror has it — the note is typed by hand and drifts (one
                # carries a mail client's UI chrome). The `[PATCH net v2]` tag
                # comes off: what is left is the subject the commit will land
                # under, which is the same thing the Patched view's title is.
                "title": strip_patch_tag(posting[1]) if posting else subject,
                # The message-id, which is the permanent lore URL. Empty when
                # the mirror has no copy; the page then falls back to a search
                # for the subject, which is what it always used to do.
                "lore": posting[0] if posting else "",
                "patch": lore_patch(posting[2]) if posting else "",
            })
        else:
            cve_id = (cve or "").strip().upper()
            # One row per CVE. Several findings can share one — the same defect
            # reached by different routes — and the fix is one fix.
            if cve_id:
                if cve_id in cves_seen:
                    continue
                cves_seen.add(cve_id)
            fix = fix_commit_of(commit_link)
            # Every column in this view derives from the CVE or the commit, so a
            # row with neither draws four dashes and says nothing. Two records
            # are in that state: marked Fixed, with commit_link, cve_number and
            # description all empty and only "CVE Claimed" typed in the notes.
            # Filling in either field in claudeManager brings the row back.
            if not cve_id and not fix:
                incomplete += 1
                states[s] -= 1    # not listed, so not counted as fixed either
                continue
            bugs.append({
                "view": view,
                "cve": cve_id,
                "commit": fix,
                "title": commit_title(fix),
                "cvss": cvss_score(cve_id),
            })

    # Aggregates only, and only for what the page actually shows: a count per
    # stage. Bug types are deliberately not emitted — the page dropped that
    # section, and an aggregate nobody displays is still published to anyone who
    # fetches the JSON.
    #
    # The CVE list went the same way. The Info page no longer carries a CVE
    # table — the numbers live on the rows they belong to, in the Patched view —
    # so the list of fixing commits and their subject lines is not published at
    # all any more. Only the count remains, and it now counts the CVEs actually
    # on the register's own rows.
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "counts": {
            "bugs": len(bugs),
            "with_report": len(bugs) - missing_report,
            "fixed": states.get("Fixed", 0),
            # Everything that reached upstream. A fixed finding was necessarily
            # reported first, so counting only the rows still sitting in
            # "Reported" understates it — they are successive points on the same
            # road, not alternatives.
            "reported": states.get("Reported", 0) + states.get("Fixed", 0),
            "scooped": scooped,
            "incomplete": incomplete,
            "merged_links": merged,
            "cves": len(cves_seen),
        },
        "states": states,
        "views": {
            VIEW_VULNERABLE: sum(1 for b in bugs if b["view"] == VIEW_VULNERABLE),
            VIEW_PROCESSING: sum(1 for b in bugs if b["view"] == VIEW_PROCESSING),
            VIEW_PATCHED: sum(1 for b in bugs if b["view"] == VIEW_PATCHED),
        },
        "bugs": bugs,
    }


def main() -> None:
    data = collect()
    # Before the file exists, not after: the check is worth nothing if the
    # thing it guards has already been written where a server can serve it.
    check_published(data["bugs"])
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, OUT)  # atomic, so a reader never sees a half-written file
    c = data["counts"]
    print(f"{c['bugs']} bugs -> {OUT}")
    print(f"  with report.md : {c['with_report']}")
    # Not a published count — the page has no place for it — but the operator
    # needs it: a Processing row the mirror could not place keeps its typed
    # subject and a lore *search*, and shows no patch at all. A large number
    # here usually means the mirror is behind, or the list the patch went to is
    # not one of the mirrored ones.
    proc = [b for b in data["bugs"] if b["view"] == VIEW_PROCESSING]
    placed = sum(1 for b in proc if b["lore"])
    print(f"  on lore        : {placed}/{len(proc)} processing rows")


if __name__ == "__main__":
    main()
