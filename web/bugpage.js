// A bug's page. The shell comes from the Pages Function (mirrored by
// preview.py); this is the part worth keeping in one file.
//
// The report is one plain-text document with `== Section ====` rules in it,
// which is the shape it needs as mail. Here those rules become headings and
// each section becomes a block that scrolls on its own, so a 300-line sanitizer report
// does not push the page sideways.

const REPORT = document.getElementById("report");
const RULE = /^== (.+?) =+$/;

// The crash and the reproducer are program output and source; the rest of the
// report is text that happens to have arrived preformatted.
const CODE = new Set(["Sanitizer Report", "Reproducer"]);

// The clipboard API is undefined outside a secure context, and the preview is
// served over plain http, so the textarea route has to exist rather than being
// a nicety -- without it copy silently does nothing there.
function copy(text) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.append(ta);
  ta.select();
  try { document.execCommand("copy"); } finally { ta.remove(); }
  return Promise.resolve();
}

function copyButton(getText) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "copybtn";
  b.title = "copy";
  b.textContent = "\u29C9";                 // two overlapping squares
  b.addEventListener("click", () => {
    copy(getText()).then(() => {
      b.textContent = "\u2713";             // check, briefly
      setTimeout(() => { b.textContent = "\u29C9"; }, 1200);
    });
  });
  return b;
}

// The report is plain text because it has to be mail; on a page its URLs and
// addresses are worth being clickable. Walks text nodes rather than rewriting
// innerHTML, so anything already added to a block survives.
// A URL, an address, or a commit cited the way the kernel cites one --
// twelve hex followed by its subject in quotes. That trailing `("` is what
// keeps this off the hex addresses in a sanitizer report.
const STABLE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=";
const LINK = /(https?:\/\/[^\s<>"')]+)|\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b|\b([0-9a-f]{12,40})\b(?= \(")/gi;

function linkify(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const texts = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) texts.push(n);

  for (const node of texts) {
    const text = node.nodeValue;
    LINK.lastIndex = 0;
    if (!LINK.test(text)) continue;
    LINK.lastIndex = 0;

    const frag = document.createDocumentFragment();
    let last = 0, m;
    while ((m = LINK.exec(text))) {
      if (m.index > last) frag.append(text.slice(last, m.index));
      const a = document.createElement("a");
      a.textContent = m[0];                    // shown as the report wrote it
      if (m[3]) {
        a.href = STABLE + m[3];
        a.target = "_blank";
        a.rel = "noopener";
      } else if (!m[1]) {
        a.href = `mailto:${m[2]}`;
      } else {
        // A link to this site resolves against wherever the page is being
        // served, so it works on the preview and on bugs.sh alike. The text
        // still reads as the absolute URL, because that is what the mailed
        // report says and the page should not appear to disagree with it.
        const u = new URL(m[1]);
        const own = u.hostname === "bugs.sh" || u.hostname === location.hostname;
        a.href = own ? u.pathname + u.search + u.hash : m[1];
        if (!own) { a.target = "_blank"; a.rel = "noopener"; }
      }
      frag.append(a);
      last = m.index + m[0].length;
    }
    if (last < text.length) frag.append(text.slice(last));
    node.replaceWith(frag);
  }
}

fetch(REPORT.dataset.src)
  .then(r => r.ok ? r.text() : Promise.reject(r.status))
  .then(text => {
    REPORT.textContent = "";

    // The page is the report and nothing else, so the subject is not repeated
    // as a heading -- it is already the first line of the mail. It does name
    // the browser tab, which is not part of the page.
    const subj = /^Subject:\s*(?:\[[^\]]*\]\s*)?(.+)$/m.exec(text);
    if (subj) document.title = subj[1].trim();
    let box = null;

    for (const line of text.split("\n")) {
      // The mail's own signature rule. What follows is the footer, not part
      // of the reproducer that happens to precede it.
      if (line.trimEnd() === "---") {
        box = document.createElement("pre");
        box.className = "foot";
        REPORT.append(document.createElement("hr"), box);
        continue;
      }
      const m = RULE.exec(line);
      if (m) {
        const h = document.createElement("h2");
        h.textContent = m[1];
        // The register links a column straight at the part of the report that
        // answers it, so each section is addressable: /b/<id>#sanitizer-report.
        h.id = m[1].toLowerCase().replace(/[^a-z0-9]+/g, "-");
        REPORT.append(h);
        box = document.createElement("pre");
        if (CODE.has(m[1])) {
          box.className = "code";
          h.append(copyButton(() => box.textContent));
        }
        REPORT.append(box);
        continue;
      }
      if (!box) {                       // headers and the opening block
        box = document.createElement("pre");
        box.className = "head";
        REPORT.append(box);
      }
      box.textContent += line + "\n";
    }

    // Each block inherits the blank lines the mail used to separate its
    // sections. On a page the headings already do that, so they are only gaps.
    for (const pre of REPORT.querySelectorAll("pre")) {
      pre.textContent = pre.textContent.replace(/^\n+|\n+$/g, "");
      if (!pre.textContent.trim()) pre.remove();
    }

    linkify(REPORT);

    // The trailer is the one line a maintainer copies verbatim into a commit,
    // so it gets its own control rather than making them select it by hand.
    for (const pre of REPORT.querySelectorAll("pre")) {
      const m = /^Reported-by:[^\n]*/m.exec(pre.textContent);
      if (!m) continue;
      const cut = m.index + m[0].length;
      const head = pre.textContent.slice(0, cut);
      const tail = pre.textContent.slice(cut);
      // The same trailer, kept in the corner so it can be copied from
      // anywhere in a report that is several hundred lines long.
      const bar = document.createElement("button");
      bar.type = "button";
      bar.className = "trailerbar";
      bar.title = m[0];
      const label = () => { bar.textContent = "\u29C9  Copy Reported-by Tag"; };
      label();
      bar.addEventListener("click", () => {
        copy(m[0]).then(() => {
          bar.textContent = "\u2713  Copied";
          setTimeout(label, 1200);
        });
      });
      document.body.append(bar);

      // In the body it stays ordinary text: the pinned copy in the corner is
      // the one that needs to stand out.
      pre.textContent = "";
      pre.append(head, tail);
      // Rebuilding the block from two strings threw away everything linkify()
      // put in it, and this is the block that carries the artifact URLs -- the
      // trailer and the "Available on:" links live in the same section, so the
      // one place a reader is given links is the one place they were lost.
      linkify(pre);
    }
  })
  .then(() => {
    // The fragment was resolved before the report existed, so honour it now.
    if (location.hash) document.querySelector(location.hash)?.scrollIntoView();
  })
  .catch(e => { REPORT.textContent = `could not load the report (${e})`; });
