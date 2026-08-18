#!/bin/sh
# Mail the bug report. The patch is a separate mail with separate
# recipients -- /mail-patch writes send-email.sh beside this for that.
# Nothing to format-patch here: the .eml carries its own Subject
# and body, so there is nothing to format-patch.
#
# --to is the subsystem list and the maintainers, --cc the reviewers:
# syzbot's split, so an automated report arrives addressed the way a
# maintainer is used to seeing one. lkml is Cc when a subsystem list
# was found and To only when none was.
#
# Recipients come from get_maintainer.pl over patch.diff where there is
# one, and otherwise over the single guilty frame of the crash.
#
# The From must stay on the onboarded domain or Cloudflare refuses the
# submission and DMARC fails at vger. If 465 is filtered where you are,
# `mkbugreport.py --send` posts the same mail over the REST API instead.

: "${CF_API_TOKEN:?set CF_API_TOKEN, the password for this submission}"

git send-email \
  --smtp-server=smtp.mx.cloudflare.net \
  --smtp-server-port=465 \
  --smtp-encryption=ssl \
  --smtp-user=api_token \
  --smtp-pass="$CF_API_TOKEN" \
  --from='co <co+4638111fe2a12980@bugs.sh>' \
  --to='Subash Abhinov Kasiviswanathan <subash.a.kasiviswanathan@oss.qualcomm.com>' \
  --to='Sean Tranchetti <sean.tranchetti@oss.qualcomm.com>' \
  --to='Andrew Lunn <andrew+netdev@lunn.ch>' \
  --to='"David S. Miller" <davem@davemloft.net>' \
  --to='Eric Dumazet <edumazet@google.com>' \
  --to='Jakub Kicinski <kuba@kernel.org>' \
  --to='Paolo Abeni <pabeni@redhat.com>' \
  --to=netdev@vger.kernel.org \
  --cc=linux-kernel@vger.kernel.org \
  ./bugreport.eml
