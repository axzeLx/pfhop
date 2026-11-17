// pfhop UI helpers. No inline scripts (strict CSP).

// Attach the CSRF token to every htmx request.
document.addEventListener("htmx:configRequest", function (evt) {
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) evt.detail.headers["X-CSRF-Token"] = meta.content;
});

// Pause auto-refresh of tables while the user has rows selected.
document.addEventListener("htmx:beforeRequest", function (evt) {
  var elt = evt.detail.elt;
  if (elt && elt.hasAttribute("data-pause-on-select") &&
      document.querySelector("input.qsel:checked")) {
    evt.preventDefault();
  }
});

function selectedCount() {
  return document.querySelectorAll("input.qsel:checked").length;
}

function updateSelection() {
  var n = selectedCount();
  var el = document.getElementById("selcount");
  if (el) el.textContent = n;
  var all = document.getElementById("selall");
  if (all) {
    var boxes = document.querySelectorAll("input.qsel");
    all.checked = boxes.length > 0 && n === boxes.length;
    all.indeterminate = n > 0 && n < boxes.length;
  }
}

// Confirmations. Plain forms use data-confirm="..."; the bulk bar checks the
// clicked button (evt.submitter).
document.addEventListener("submit", function (evt) {
  var form = evt.target;
  var btn = evt.submitter;
  if (form.hasAttribute("data-confirm-bulk")) {
    if (btn && btn.hasAttribute("data-flush")) {
      if (!window.confirm("Try to deliver all queued messages now?")) evt.preventDefault();
      return;
    }
    var n = selectedCount();
    if (n === 0) {
      evt.preventDefault();
      var sc = document.getElementById("selcount");
      if (sc) {
        sc.parentNode.classList.add("flash-text");
        setTimeout(function () { sc.parentNode.classList.remove("flash-text"); }, 1200);
      }
      return;
    }
    if (btn && btn.hasAttribute("data-confirm-delete") &&
        !window.confirm("Delete " + n + " message(s) from the queue? This cannot be undone.")) {
      evt.preventDefault();
    }
    return;
  }
  var msg = form.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) evt.preventDefault();
});

// Client-side table filters: <input data-filter="#table"> and <select data-status-filter="#table">
function applyFilters(table) {
  if (!table) return;
  var sel = "#" + table.id;
  var text = document.querySelector('[data-filter="' + sel + '"]');
  var status = document.querySelector('[data-status-filter="' + sel + '"]');
  var q = text ? text.value.toLowerCase() : "";
  var st = status ? status.value : "";
  table.querySelectorAll("tbody tr").forEach(function (tr) {
    var okText = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
    var okStatus = !st || tr.getAttribute("data-status") === st;
    tr.hidden = !(okText && okStatus);
  });
}

// Select-all checkbox, selection counter, status filter.
document.addEventListener("change", function (evt) {
  var t = evt.target;
  if (t.id === "selall") {
    document.querySelectorAll("input.qsel").forEach(function (b) {
      if (!b.closest("tr").hidden) b.checked = t.checked;
    });
  }
  if (t.id === "selall" || t.classList.contains("qsel")) updateSelection();
  if (t.hasAttribute("data-status-filter")) {
    applyFilters(document.querySelector(t.getAttribute("data-status-filter")));
  }
});

document.addEventListener("input", function (evt) {
  var sel = evt.target.getAttribute("data-filter");
  if (sel) applyFilters(document.querySelector(sel));
});

// Re-apply filters / selection state after htmx replaces table rows.
document.addEventListener("htmx:afterSwap", function (evt) {
  var target = evt.detail.target;
  var table = target && target.closest ? target.closest("table") : null;
  if (table && table.id) applyFilters(table);
  updateSelection();
});

// Collapsible sidebar. The state lives in a cookie so the server renders the
// right layout on the next page load (no flicker).
document.addEventListener("click", function (evt) {
  var btn = evt.target.closest ? evt.target.closest("#sb-toggle") : null;
  if (!btn) return;
  var collapsed = document.body.classList.toggle("sb-collapsed");
  var secure = location.protocol === "https:" ? "; Secure" : "";
  document.cookie = "pfhop_sb=" + (collapsed ? "1" : "0") +
    "; Path=/; Max-Age=31536000; SameSite=Strict" + secure;
});

// Reason / response cells: click to expand the full text. Expanded cells are
// remembered by data-key so auto-refresh does not collapse them again.
var openClamps = {};
document.addEventListener("click", function (evt) {
  var el = evt.target.closest ? evt.target.closest(".clamp") : null;
  if (!el) return;
  var open = el.classList.toggle("open");
  var key = el.getAttribute("data-key");
  if (key) { if (open) openClamps[key] = true; else delete openClamps[key]; }
});
document.addEventListener("htmx:afterSwap", function (evt) {
  var target = evt.detail.target;
  if (!target || !target.querySelectorAll) return;
  target.querySelectorAll(".clamp[data-key]").forEach(function (el) {
    if (openClamps[el.getAttribute("data-key")]) el.classList.add("open");
  });
});

// Relay form: show only the fields that apply to the chosen relay type.
document.addEventListener("change", function (evt) {
  var t = evt.target;
  if (t.name !== "kind" || !t.closest) return;
  var form = t.closest("[data-relay-form]");
  if (!form) return;
  form.setAttribute("data-kind", t.value);
  var host = form.querySelector('input[name="host"]');
  if (host) host.required = t.value === "smtp";
});

// Logs page: show the custom date fields only for the "Custom range" preset.
document.addEventListener("change", function (evt) {
  var sel = evt.target;
  if (!sel.hasAttribute || !sel.hasAttribute("data-period-select")) return;
  var custom = sel.value === "custom";
  document.querySelectorAll("[data-custom-range]").forEach(function (box) {
    box.hidden = !custom;
    box.querySelectorAll("input").forEach(function (inp) { inp.disabled = !custom; });
  });
  if (!custom) {
    var help = sel.parentNode.querySelector(".help");
    if (help) help.remove();
  }
});
