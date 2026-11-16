"use strict";

const CREDIT_ROLES = {
  "Signed-off-by": "Sign-off",
  "Reviewed-by": "Review",
  "Tested-by": "Testing",
  "Acked-by": "Acknowledgement",
  "Suggested-by": "Suggestion",
  "Co-developed-by": "Co-development",
  "Reported-by": "Reporting",
};

// Derive attribution from the register on every load; no separate roster to
// update when CVEs or fixing commits change.
function groupContributors(bugs) {
  const people = new Map();
  const cves = new Set();
  const credited = new Set();
  for (const bug of bugs) {
    if (bug.view !== "patched" || !/^CVE-\d{4}-\d{4,}$/.test(bug.cve || "")) continue;
    cves.add(bug.cve);
    const credits = bug.credits ?? (bug.signed_off_by || []).map(name =>
      ({name, tags: ["Signed-off-by"]}));
    for (const credit of credits) {
      const name = credit.name.normalize("NFC").trim().replace(/\s+/g, " ");
      const tags = credit.tags.filter(tag => Object.hasOwn(CREDIT_ROLES, tag));
      if (!name || !tags.length) continue;
      const key = name.toLocaleLowerCase("en-US");
      if (!people.has(key)) people.set(key, {name, cves: new Map(), tags: new Set()});
      const person = people.get(key);
      tags.forEach(tag => person.tags.add(tag));
      const previous = person.cves.get(bug.cve);
      person.cves.set(bug.cve, {
        ...bug, tags: [...new Set([...(previous?.tags || []), ...tags])],
      });
      credited.add(bug.cve);
    }
  }
  return {
    people: [...people.values()].sort((a, b) =>
      b.cves.size - a.cves.size || a.name.localeCompare(b.name)),
    cves,
    missing: [...cves].filter(cve => !credited.has(cve)).sort(),
  };
}

const summary = document.getElementById("contributor-summary");
const list = document.getElementById("contributors");
const expandedContributors = new Set();
let cveLists = [];
let data = null;

function updateCveLists() {
  // Measure actual wrapped rows, so the limit also holds on narrow screens.
  for (const {items, toggleItem} of cveLists) {
    toggleItem.hidden = true;
    items.forEach(item => { item.hidden = false; });
  }
  const layouts = cveLists.map(entry => {
    let lines = 0, top = -Infinity, visible = 0;
    for (const item of entry.items) {
      const itemTop = item.getBoundingClientRect().top;
      if (itemTop > top + 1) { lines++; top = itemTop; }
      if (lines <= 3) visible++;
    }
    const slotWidth = visible ? getComputedStyle(entry.items[visible - 1]).width : "";
    return {...entry, visible, slotWidth};
  });
  for (const {key, items, button, toggleItem, visible, slotWidth} of layouts) {
    const expanded = expandedContributors.has(key);
    const truncated = visible < items.length;
    // The final slot in row three becomes the expansion control. Matching
    // its width keeps the button in that slot at every screen size.
    const limit = truncated ? visible - 1 : visible;
    items.forEach((item, index) => { item.hidden = !expanded && index >= limit; });
    toggleItem.style.width = expanded ? "" : slotWidth;
    toggleItem.hidden = button.hidden = !truncated;
    button.setAttribute("aria-expanded", String(expanded));
    button.textContent = expanded ? "Show less" : `Show all ${items.length} CVEs`;
  }
}

let resizeFrame;
window.addEventListener("resize", () => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(updateCveLists);
});

function renderContributors() {
  if (!data) return;
  const people = data.people;
  summary.textContent = `${people.length} contributors · ${data.cves.size} assigned CVEs`;

  const fragment = document.createDocumentFragment();
  cveLists = [];
  for (const person of people) {
    const row = document.createElement("article");
    row.className = "contributor";
    const head = document.createElement("div");
    const name = document.createElement("h2");
    name.textContent = person.name;
    const count = document.createElement("p");
    count.className = "contributor-count";
    count.textContent = `${person.cves.size} ${person.cves.size === 1 ? "CVE" : "CVEs"}`;
    const roles = document.createElement("p");
    roles.className = "contributor-roles";
    roles.textContent = Object.keys(CREDIT_ROLES).filter(tag => person.tags.has(tag))
      .map(tag => CREDIT_ROLES[tag]).join(" · ");
    head.append(name, count, roles);

    const cves = document.createElement("ul");
    cves.className = "contributor-cves";
    cves.id = `contributor-cves-${cveLists.length}`;
    cves.setAttribute("aria-label", `CVEs contributed by ${person.name}`);
    for (const [cve, bug] of [...person.cves].sort(([a], [b]) =>
      b.localeCompare(a, "en", {numeric: true}))) {
      const item = document.createElement("li");
      const hasPatch = /^[a-f0-9]{7,40}$/.test(bug.commit || "");
      const link = document.createElement(hasPatch ? "a" : "span");
      link.className = "contributor-cve-label";
      link.textContent = cve;
      link.title = [bug.title, bug.tags.join(", ")].filter(Boolean).join(" — ");
      if (hasPatch) {
        link.href = `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=${bug.commit}`;
        link.target = "_blank";
        link.rel = "noopener";
        link.setAttribute("aria-label", `Fixing patch for ${cve}`);
      }
      item.append(link);
      cves.append(item);
    }
    const group = document.createElement("div");
    group.className = "contributor-cve-group";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "contributor-toggle";
    button.hidden = true;
    button.setAttribute("aria-controls", cves.id);
    const toggleItem = document.createElement("li");
    toggleItem.className = "contributor-toggle-item";
    toggleItem.hidden = true;
    toggleItem.append(button);
    const key = person.name.toLocaleLowerCase("en-US");
    button.addEventListener("click", () => {
      if (expandedContributors.has(key)) expandedContributors.delete(key);
      else expandedContributors.add(key);
      updateCveLists();
    });
    cveLists.push({key, items: [...cves.children], button, toggleItem});
    cves.append(toggleItem);
    group.append(cves);
    row.append(head, group);
    fragment.append(row);
  }
  list.replaceChildren(fragment);
  updateCveLists();
  const empty = document.getElementById("contributor-empty");
  empty.hidden = people.length !== 0;
}

async function loadContributors() {
  try {
    const response = await fetch("bugs.json", {cache: "no-store"});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const register = await response.json();
    if (!Array.isArray(register.bugs)) throw new Error("Invalid register");
    data = groupContributors(register.bugs);
    renderContributors();
    const coverage = document.getElementById("contributor-coverage");
    coverage.hidden = data.missing.length === 0;
    coverage.textContent = `Contributor information is not yet available for: ${data.missing.join(", ")}.`;
    document.getElementById("foot").textContent =
      `Data extracted ${register.generated_at || "—"}`;
  } catch (error) {
    summary.textContent = `Could not load contributors (${error.message}). Reload the page to try again.`;
  }
}

loadContributors();
