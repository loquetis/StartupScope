/* StartupScope UI. Text only (Kit.el), no innerHTML. Items are acted on by id; the page never sends paths. */
(() => {
  "use strict";
  const { $, el, clear, toast, api, post, num, dt, ago, dur, initTheme, confirmDialog } = window.Kit;
  initTheme($("#theme"));
  const S = { status: null, items: [], sel: null, view: "items", polling: null, lastScan: null, busy: new Set() };
  const TITLES = { items: "Startup items", changes: "Changes & undo", about: "About & safety" };
  const SIG = { signed: ["Signed", "ok"], unsigned: ["Unsigned", "warn"], invalid: ["Bad signature", "danger"], missing: ["File missing", "muted-badge"], pending: ["Checking…", "muted-badge"], unknown: ["Unknown", "muted-badge"] };

  function show(v) {
    S.view = v;
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
    $("#view-title").textContent = TITLES[v];
    ["items", "changes", "about"].forEach((n) => { $("#v-" + n).hidden = n !== v; });
    if (v === "changes") loadChanges();
    if (v === "about") renderAbout();
  }
  document.querySelectorAll(".nav-btn").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

  // ------------------------------------------------------------ data
  async function loadStatus() {
    try { S.status = await api("/api/status"); } catch (e) { $("#status").textContent = "Cannot reach StartupScope: " + e.message; return; }
    const st = S.status;
    $("#status").textContent = st.scanning ? "Scanning…" : st.verifying ? "Checking signatures (" + st.verified + "/" + st.to_verify + ")…" : st.last_scan ? "Scanned " + ago(st.last_scan) : "";
    $("#side-text").textContent = st.scanning ? "Scanning your startup items…" : st.verifying ? "Checking signatures…" : st.total + " items · " + st.enabled + " enabled";
    $("#n-items").textContent = st.total ? String(st.total) : "";
    renderBanners(); renderCards();
    if (S.lastScan !== st.last_scan || st.verifying || S.wasVerifying) { S.lastScan = st.last_scan; S.wasVerifying = st.verifying; await loadItems(); }
    schedule();
  }
  async function loadItems() {
    try { S.items = (await api("/api/items")).items; } catch (e) { return; }
    renderRows();
  }
  function schedule() {
    clearTimeout(S.polling);
    const busy = S.status && (S.status.scanning || S.status.verifying);
    S.polling = setTimeout(loadStatus, busy ? 900 : 6000);
  }

  // ------------------------------------------------------------ top of page
  function renderBanners() {
    const st = S.status, box = clear($("#banners"));
    if (!st) return;
    if (!st.admin) box.appendChild(el("p", { className: "notice", text: "Running without administrator rights. You can change your own startup items; items for all users, services and other users' tasks are shown but locked." }));
    (st.errors || []).forEach((e) => box.appendChild(el("p", { className: "notice warn", text: e })));
  }
  function card(label, value, sub) { return el("div", { className: "card" }, el("div", { className: "label", text: label }), el("div", { className: "value", text: value }), el("div", { className: "sub", text: sub || "" })); }
  function renderCards() {
    const st = S.status, box = clear($("#cards"));
    box.appendChild(card("Startup items", num(st.total), num(st.enabled) + " enabled"));
    const c = st.counts || {};
    box.appendChild(card("Apps & shortcuts", num((c.run || 0) + (c.folder || 0)), num(c.task || 0) + " tasks · " + num(c.service || 0) + " services"));
    box.appendChild(card("Last boot time", st.impact.boot_ms != null ? (st.impact.boot_ms / 1000).toFixed(1) + " s" : "n/a", st.impact.boot_ms != null ? (st.impact.boot_time ? "recorded " + ago(st.impact.boot_time) : "from the Windows event log") : st.impact.ok ? "not recorded recently" : "log needs admin"));
    box.appendChild(card("Unsigned", num(st.unsigned), st.verifying ? "still checking…" : "no valid signature"));
  }

  // ------------------------------------------------------------ list
  function filtered() {
    const q = $("#q").value.trim().toLowerCase(), kind = $("#f-kind").value, hideWin = $("#f-win").checked, off = $("#f-off").checked;
    let rows = S.items.filter((i) => (kind === "all" || i.kind === kind) && !(hideWin && i.protected) && !(off && i.enabled)
      && (!q || [i.display, i.name, i.publisher, i.command, i.source].some((s) => (s || "").toLowerCase().includes(q))));
    const sort = $("#f-sort").value;
    const cmp = { impact: (a, b) => (b.impact_ms || -1) - (a.impact_ms || -1) || a.display.localeCompare(b.display), name: (a, b) => a.display.localeCompare(b.display),
      publisher: (a, b) => (a.publisher || "~").localeCompare(b.publisher || "~") || a.display.localeCompare(b.display), type: (a, b) => a.type.localeCompare(b.type) || a.display.localeCompare(b.display) }[sort];
    rows = rows.slice().sort(cmp);
    return rows;
  }
  function impactCell(i) {
    if (i.impact_ms == null) return el("span", { className: "imp-na", text: "n/a", title: S.status && S.status.impact.note || "" });
    return el("span", { className: "imp-" + i.impact, text: i.impact + " · " + (i.impact_ms / 1000).toFixed(1) + " s", title: "Slowest recently logged start: " + i.impact_ms + " ms" });
  }
  function switchCell(i) {
    if (!i.can_toggle) return el("span", { className: "lock", text: i.protected ? "Windows" : "Admin", title: i.reason || "" });
    const b = el("button", { type: "button", className: "switch", role: "switch", "aria-checked": i.enabled ? "true" : "false", "aria-label": (i.enabled ? "Disable " : "Enable ") + i.display, title: i.enabled ? "Click to disable at startup" : "Click to enable at startup" });
    if (S.busy.has(i.id)) b.disabled = true;
    b.addEventListener("click", (e) => { e.stopPropagation(); toggle(i, !i.enabled); });
    return b;
  }
  function renderRows() {
    const rows = filtered(), body = clear($("#rows"));
    for (const i of rows) {
      const sg = SIG[i.sig] || SIG.unknown;
      const tr = el("tr", { className: (i.enabled ? "" : "off ") + (S.sel === i.id ? "sel selectable" : "selectable"), "data-id": i.id, tabindex: "0" },
        el("td", { className: "c-sw" }, switchCell(i)),
        el("td", {}, el("div", { className: "nm", text: i.display, title: i.display }), el("div", { className: "cmd", text: i.command || i.location, title: i.command || i.location })),
        el("td", {}, el("div", { className: "sigline" }, el("span", { className: "badge " + sg[1], text: sg[0], title: i.sig_detail || "" }), el("span", { className: "pub", text: i.publisher || "", title: i.publisher || "" }))),
        el("td", { text: i.type, title: i.source }),
        el("td", {}, impactCell(i)));
      tr.addEventListener("click", () => select(i.id));
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") select(i.id); });
      body.appendChild(tr);
    }
    const hidden = S.items.filter((i) => i.protected).length;
    $("#empty").hidden = rows.length > 0;
    $("#empty").textContent = S.status && S.status.scanning && !S.items.length ? "Scanning…" : "Nothing matches these filters.";
    $("#count").textContent = rows.length + " shown of " + S.items.length + (hidden && $("#f-win").checked ? " · " + hidden + " Windows components hidden" : "");
    renderDetail();
  }
  function select(id) { S.sel = S.sel === id ? null : id; renderRows(); }
  function renderDetail() {
    const box = clear($("#detail")), i = S.items.find((x) => x.id === S.sel);
    if (!i) { box.hidden = true; return; }
    box.hidden = false;
    const dl = el("dl", { className: "deflist" });
    const add = (k, v) => { if (v) { dl.appendChild(el("dt", { text: k })); dl.appendChild(el("dd", { text: v })); } };
    add("Type", i.type + " · " + i.source);
    add("Location", i.location);
    add("Command", i.command);
    add("File", i.target);
    add("Publisher", (i.publisher || "unknown") + " — " + ((SIG[i.sig] || SIG.unknown)[0]) + (i.sig_detail ? " (" + i.sig_detail + ")" : ""));
    add("Description", i.desc);
    if (i.extra) {
      if (i.extra.triggers && i.extra.triggers.length) add("Starts", i.extra.triggers.join(", "));
      add("Runs as", i.extra.runs_as || i.extra.account);
      add("Start type", i.extra.start);
    }
    add("Boot impact", i.impact_ms == null ? "n/a" : i.impact + " (" + (i.impact_ms / 1000).toFixed(1) + " s, slowest recently logged)");
    add("Changing it", i.can_toggle ? "You can switch it off and on here." : i.reason);
    const rev = el("button", { type: "button", text: "Show file in folder" });
    rev.addEventListener("click", async () => { try { const r = await post("/api/reveal", { id: i.id }); if (!r.ok) toast(r.error, true); } catch (e) { toast(e.message, true); } });
    const cp = el("button", { type: "button", text: "Copy command" });
    cp.addEventListener("click", async () => { try { await navigator.clipboard.writeText(i.command || ""); toast("Copied"); } catch { toast("Could not copy", true); } });
    box.appendChild(el("h2", { text: i.display }));
    box.appendChild(dl);
    box.appendChild(el("div", { className: "actions-row" }, rev, cp));
  }
  ["q", "f-kind", "f-sort", "f-win", "f-off"].forEach((id) => $("#" + id).addEventListener(id === "q" ? "input" : "change", renderRows));
  $("#btn-refresh").addEventListener("click", async () => { try { await post("/api/refresh", {}); toast("Refreshing…"); S.lastScan = null; loadStatus(); } catch (e) { toast(e.message, true); } });

  // ------------------------------------------------------------ toggling
  async function toggle(i, enable, confirmed) {
    S.busy.add(i.id); renderRows();
    try {
      const r = await post("/api/toggle", { id: i.id, enabled: enable, confirm: confirmed === true });
      if (r.confirm === "service") {
        S.busy.delete(i.id); renderRows();
        const ok = await confirmDialog((enable ? "Enable " : "Disable ") + i.display + "?", enable ? "This sets the service back to start automatically." : "This sets the service to Manual, so it no longer starts with Windows. Programs that need it can still start it. You can undo this under “Changes & undo”.", enable ? "Enable" : "Disable", !enable);
        if (ok) return toggle(i, enable, true);
        return;
      }
      if (!r.ok) { toast(r.error || "Could not change it", true); return; }
      const idx = S.items.findIndex((x) => x.id === i.id);
      if (idx >= 0) S.items[idx] = r.item;
      toast(r.item.display + (r.item.enabled ? " will start with Windows again." : " will no longer start with Windows.") + " Undo is under “Changes & undo”.");
      loadChangesCount(); loadStatus();
    } catch (e) { toast(e.message, true); }
    finally { S.busy.delete(i.id); renderRows(); }
  }

  // ------------------------------------------------------------ changes
  async function loadChangesCount() { try { const r = await api("/api/changes"); const n = r.changes.filter((c) => !c.undone).length; $("#n-changes").textContent = n ? String(n) : ""; return r; } catch { return null; } }
  async function loadChanges() {
    const r = await loadChangesCount(); if (!r) return;
    $("#backup-dir").textContent = r.backup_dir;
    const body = clear($("#chg-rows"));
    $("#chg-empty").hidden = r.changes.length > 0;
    for (const c of r.changes) {
      const undo = el("button", { type: "button", className: "small", text: "Undo" });
      undo.addEventListener("click", async () => {
        undo.disabled = true;
        try { const x = await post("/api/undo", { change_id: c.id }); if (!x.ok) toast(x.error, true); else { toast("Restored the original setting."); await loadStatus(); } } catch (e) { toast(e.message, true); }
        loadChanges();
      });
      body.appendChild(el("tr", { className: c.undone ? "off" : "" },
        el("td", { text: dt(c.time) }), el("td", {}, el("div", { className: "nm", text: c.display || c.item }), el("div", { className: "cmd", text: c.command || "", title: c.command || "" })),
        el("td", { text: (c.action === "disable" ? "Disabled" : "Enabled") + (c.undone ? " (undone)" : "") }), el("td", { text: c.source || "" }),
        el("td", {}, c.undone ? null : undo)));
    }
  }
  function renderAbout() {
    const st = S.status; if (!st) return;
    $("#about-impact").textContent = st.impact.ok ? (st.impact.note + " Items Windows flagged show High, Medium or Low (High is 3 s or more, Medium 1–3 s).") : (st.impact.note || "n/a") + " Everything shows n/a until the log is readable.";
    $("#data-dir").textContent = st.data_dir;
  }

  loadStatus(); loadChangesCount();
  document.addEventListener("visibilitychange", () => { if (!document.hidden) loadStatus(); });
})();
