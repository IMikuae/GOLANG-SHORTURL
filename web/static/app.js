// app.js — port ToastProvider + fetch helper + util tanggal (vanilla JS).
async function api(path, method, body) {
  const res = await fetch(path, {
    method: method || "GET",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* abaikan */ }
  if (!res.ok) {
    const err = new Error(data.error || ("Gagal (" + res.status + ")"));
    err.status = res.status;
    throw err;
  }
  return data;
}

// ── Toast (port ToastProvider.jsx) ──
const TOAST_ICONS = {
  success: "s-check",
  error: "s-x-mark",
  warning: "s-exclamation-triangle",
  info: "s-information-circle",
};
function toast(message, variant) {
  variant = variant || "info";
  const root = document.getElementById("toast-root");
  if (!root) { alert(message); return; }
  const el = document.createElement("div");
  el.setAttribute("role", "status");
  const border =
    variant === "success" ? "border-l-success" :
    variant === "error" ? "border-l-error" :
    variant === "warning" ? "border-l-warning" : "border-l-primary";
  const iconColor =
    variant === "success" ? "text-success" :
    variant === "error" ? "text-error" :
    variant === "warning" ? "text-warning" : "text-primary-hover";
  el.className =
    "flex items-center gap-3 px-4 py-3 rounded-lg border border-border " +
    "shadow-lg shadow-black/30 backdrop-blur animate-slide-in-right " +
    "border-l-2 bg-surface-elevated " + border;
  el.style.minWidth = "280px";
  el.style.maxWidth = "420px";
  el.innerHTML =
    '<svg class="w-5 h-5 shrink-0 ' + iconColor + '" aria-hidden="true">' +
    '<use href="/static/icons.svg#' + (TOAST_ICONS[variant] || TOAST_ICONS.info) + '"/></svg>' +
    '<p class="text-sm text-text-primary flex-1"></p>' +
    '<button type="button" aria-label="Tutup notifikasi" ' +
    'class="text-text-muted hover:text-text-primary text-lg leading-none">&times;</button>';
  el.querySelector("p").textContent = message;
  el.querySelector("button").addEventListener("click", () => el.remove());
  root.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Confirm dialog (port useConfirm) ──
let __confirmState = null;
function confirmDialog(message) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("confirm-overlay");
    const box = document.getElementById("confirm-box");
    const msg = document.getElementById("confirm-message");
    const okBtn = document.getElementById("confirm-ok");
    const cancelBtn = document.getElementById("confirm-cancel");
    if (!overlay || !box) {
      resolve(window.confirm(message));
      return;
    }
    if (__confirmState) __confirmState(false);
    msg.textContent = message;
    overlay.classList.remove("hidden");
    requestAnimationFrame(() => box.classList.add("animate-scale-in"));
    const done = (val) => {
      overlay.classList.add("hidden");
      box.classList.remove("animate-scale-in");
      okBtn.onclick = cancelBtn.onclick = overlay.onclick = null;
      __confirmState = null;
      resolve(val);
    };
    __confirmState = done;
    okBtn.onclick = () => done(true);
    cancelBtn.onclick = () => done(false);
    overlay.onclick = (e) => { if (e.target === overlay) done(false); };
  });
}

async function copyText(t) {
  try {
    await navigator.clipboard.writeText(t);
    return true;
  } catch (e) {
    const el = document.createElement("textarea");
    el.value = t;
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.select();
    try { document.execCommand("copy"); return true; }
    catch (e2) { return false; }
    finally { document.body.removeChild(el); }
  }
}

// "2026-10-04 13:02:57" (UTC, gaya SQLite) atau RFC3339 → Date.
function parseDbDate(s) {
  if (!s) return null;
  s = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s)) return new Date(s.replace(" ", "T") + "Z");
  return new Date(s);
}
function fmtDateId(s, opts) {
  const d = parseDbDate(s);
  if (!d || isNaN(d)) return s;
  return d.toLocaleDateString("id-ID", opts || { day: "numeric", month: "short", year: "numeric" });
}
