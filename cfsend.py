#!/usr/bin/env python3
"""Send an RFC822 message through Cloudflare's Email Sending REST API.

Exists because SMTP submission (port 465) is filtered on some networks. This
goes out over 443 instead: we hand Cloudflare a JSON description of the mail
and their infrastructure does the delivery, so the blocked leg is no longer
ours. Same token, same domain, same From — only the transport differs.

Reads a message on stdin (or a file), so it drops in wherever sendmail would:

    cfsend.py < message.eml
    cfsend.py message.eml --to someone@example.com
    git send-email --sendmail-cmd=./cfsend.py ...

Requires CF_API_TOKEN in the environment. Account id may be overridden with
CF_ACCOUNT_ID.
"""

import argparse
import email
import email.policy
import json
import os
import sys
import urllib.error
import urllib.request

ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID",
                            "33fcaab9605bd90bb8902b03f5a6429f")
API = ("https://api.cloudflare.com/client/v4/accounts/"
       "{acct}/email/sending/send")

# Headers Cloudflare sets itself, or that describe a transport we are not
# using. Everything else is forwarded so patch threading survives.
DROP = {
    "to", "from", "cc", "bcc", "subject", "reply-to",
    "content-type", "content-transfer-encoding", "mime-version",
    "return-path", "received", "dkim-signature",
}


def addrs(msg, field):
    """All addresses in a header, split on commas, as a flat list."""
    out = []
    for raw in msg.get_all(field, []):
        out += [a.strip() for a in raw.split(",") if a.strip()]
    return out


def build(raw, to_override=None, from_override=None):
    msg = email.message_from_string(raw, policy=email.policy.default)

    to = to_override or addrs(msg, "to")
    if not to:
        sys.exit("no recipient: message has no To: and --to was not given")

    sender = from_override or msg.get("from")
    if not sender:
        sys.exit("no sender: message has no From: and --from was not given")

    if msg.is_multipart():
        # Kernel mail is single-part; if that ever changes, take the text part.
        part = next((p for p in msg.walk()
                     if p.get_content_type() == "text/plain"), None)
        body = part.get_content() if part else ""
    else:
        body = msg.get_content()

    payload = {
        "to": to,
        "from": sender,
        "subject": msg.get("subject", "(no subject)"),
        # text only, never html: vger rejects HTML mail outright.
        "text": body,
    }
    for field in ("cc", "bcc"):
        if addrs(msg, field):
            payload[field] = addrs(msg, field)
    if msg.get("reply-to"):
        payload["reply_to"] = msg["reply-to"]

    # Preserve Message-Id / In-Reply-To / References so patch series thread.
    extra = {k: v for k, v in msg.items() if k.lower() not in DROP}
    if extra:
        payload["headers"] = extra

    return payload


def send(payload):
    token = os.environ.get("CF_API_TOKEN")
    if not token:
        sys.exit("CF_API_TOKEN is not set")

    body = json.dumps(payload).encode()
    if len(body) > 5 * 1024 * 1024:
        sys.exit(f"message is {len(body)/1048576:.1f} MiB; the API caps at 5 MiB")

    req = urllib.request.Request(
        API.format(acct=ACCOUNT_ID), data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            errs = json.loads(detail).get("errors", [])
            detail = "; ".join(f"{x.get('code')}: {x.get('message')}"
                               for x in errs) or detail
        except ValueError:
            pass
        sys.exit(f"HTTP {e.code} from Cloudflare — {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"could not reach the API: {e.reason}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("message", nargs="?", help="RFC822 file; stdin if omitted")
    ap.add_argument("--to", action="append", metavar="ADDR",
                    help="override recipients entirely (repeatable)")
    ap.add_argument("--from", dest="sender", metavar="ADDR",
                    help="override the From address")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the JSON that would be POSTed and stop")
    args = ap.parse_args()

    raw = (open(args.message, encoding="utf-8", errors="replace").read()
           if args.message else sys.stdin.read())
    payload = build(raw, args.to, args.sender)

    if args.dry_run:
        preview = dict(payload, text=payload["text"][:400] + " ...[trimmed]")
        print(json.dumps(preview, indent=2))
        return

    result = send(payload)
    if result.get("success"):
        ids = result.get("result") or {}
        print(f"sent to {', '.join(payload['to'])}"
              + (f"  (id {ids.get('id')})" if ids.get("id") else ""))
    else:
        sys.exit(f"send failed: {json.dumps(result.get('errors'))}")


if __name__ == "__main__":
    main()
