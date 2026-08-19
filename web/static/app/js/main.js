/**
 * Dashboard bootstrap.
 *
 * Registers lazy-loaded routes, builds the nav, opens the single
 * WebSocket connection and reflects live status/active-scan counts in
 * the chrome. Keeping this file tiny means the browser parses almost
 * nothing before first paint; views stream in on demand.
 */
import { api } from "./core/api.js";
import { bus } from "./core/bus.js";
import { initWs } from "./core/ws.js";
import { h } from "./core/dom.js";
import * as router from "./core/router.js";

// Route table — loaders are dynamic imports (code-split per view).
router.register("overview", { label: "Overview", icon: "◎", loader: () => import("./views/overview.js") });
router.register("new", { label: "New scan", icon: "＋", loader: () => import("./views/newscan.js") });
router.register("scans", { label: "Scans", icon: "▤", loader: () => import("./views/scans.js") });
router.register("tools", { label: "Tools", icon: "⚙", loader: () => import("./views/tools.js") });
// Detail is reachable via #/scan/<id> but hidden from the nav.
router.register("scan", { label: "Scan", icon: "", nav: false, loader: () => import("./views/detail.js") });

function buildChrome(user) {
  const wsDot = h("span", { class: "ws-dot ws-off", id: "ws-dot", title: "WebSocket" });
  const activeBadge = h("span", { class: "nav-badge hidden", id: "active-badge" }, "0");

  const navLinks = router.navItems().map((it) =>
    h("a", { class: "nav-link", href: `#/${it.name}`, "data-route": it.name },
      h("span", { class: "nav-ico" }, it.icon), it.label,
      it.name === "overview" ? activeBadge : null));

  const logout = h("button", {
    class: "btn btn-sm btn-ghost",
    type: "button",
    onClick: () => {
      api.clearAuthTokens();
      window.location.reload();
    },
  }, "Log out");

  const sidebar = h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, h("span", { class: "brand-mark" }, "⚛"), h("span", {}, "ATOMIC")),
    h("nav", { class: "nav" }, ...navLinks),
    h("div", { class: "sidebar-foot" },
      wsDot, h("span", { class: "muted", id: "ws-label" }, "offline"),
      h("span", { class: "muted owner-label", title: "Full owner permissions" }, `◆ ${user.username}`),
      logout));

  const outlet = h("main", { class: "outlet", id: "outlet" });
  const shell = h("div", { class: "shell" }, sidebar, outlet);
  document.body.appendChild(shell);
  router.setOutlet(outlet);

  router.onRouteChange((name) => {
    for (const a of navLinks) a.classList.toggle("active", a.dataset.route === name);
  });

  // WebSocket status indicator.
  bus.on("ws:status", ({ connected, available }) => {
    wsDot.className = "ws-dot " + (connected ? "ws-on" : available ? "ws-off" : "ws-na");
    const label = document.getElementById("ws-label");
    if (label) label.textContent = connected ? "live" : available ? "reconnecting…" : "polling";
  });

  // Active-scan badge from live events.
  const active = new Set();
  const paint = () => {
    activeBadge.textContent = String(active.size);
    activeBadge.classList.toggle("hidden", active.size === 0);
  };
  bus.on("ws:active_scans", (m) => { active.clear(); Object.keys(m || {}).forEach((k) => active.add(k)); paint(); });
  bus.on("ws:scan_started", (d) => { if (d && d.scan_id) active.add(d.scan_id); paint(); });
  bus.on("ws:scan_completed", (d) => { if (d && d.scan_id) active.delete(d.scan_id); paint(); });
}

function authScreen({ setup = false, message = "" } = {}) {
  document.body.replaceChildren();
  const title = setup ? "Create your owner account" : "Owner login";
  const subtitle = setup
    ? "First run: choose the admin password. All framework capabilities unlock after login."
    : "Sign in to unlock the scanner, tools, AI and reports.";
  const username = h("input", {
    class: "input", type: "text", value: "admin", maxlength: "64",
    autocomplete: "username", required: true,
  });
  const password = h("input", {
    class: "input", type: "password", minlength: "8",
    autocomplete: setup ? "new-password" : "current-password", required: true,
  });
  const confirmation = setup ? h("input", {
    class: "input", type: "password", minlength: "8",
    autocomplete: "new-password", required: true,
  }) : null;
  const authorized = setup ? h("input", { type: "checkbox", required: true }) : null;
  const status = h("div", { class: "auth-status" }, message);
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, setup ? "Create owner & unlock" : "Log in");
  const form = h("form", { class: "card auth-card" },
    h("div", { class: "brand auth-brand" }, h("span", { class: "brand-mark" }, "⚛"), "ATOMIC OWNER MODE"),
    h("h2", {}, title),
    h("p", { class: "muted" }, subtitle),
    h("label", {}, "Username", username),
    h("label", {}, "Password", password),
    setup ? h("p", { class: "muted auth-hint" }, "Minimum 8 characters with uppercase, lowercase and a number. Never use a password posted in chat.") : null,
    setup ? h("label", {}, "Confirm password", confirmation) : null,
    setup ? h("label", { class: "check auth-ack" }, authorized,
      "I will use active scanning and post-exploitation only on systems I own or am authorized to test.") : null,
    status,
    submit);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = "Working…";
    status.className = "auth-status";
    try {
      const data = setup
        ? await api.post("/api/auth/setup", {
            username: username.value.trim() || "admin",
            password: password.value,
            password_confirmation: confirmation.value,
            authorized_use: authorized.checked,
          })
        : await api.post("/api/auth/login", {
            username: username.value.trim(),
            password: password.value,
          });
      api.setAuthTokens(data || {});
      window.location.reload();
    } catch (error) {
      status.textContent = error.message || "Authentication failed";
      status.className = "auth-status auth-error";
      submit.disabled = false;
    }
  });

  document.body.append(h("main", { class: "auth-shell" }, form));
  password.focus();
}

async function requireOwnerLogin() {
  let setup;
  try {
    setup = await api.get("/api/auth/setup/status", { cache: false });
  } catch (error) {
    authScreen({ message: error.message || "Authentication service unavailable" });
    return null;
  }
  if (setup && setup.required) {
    api.clearAuthTokens();
    authScreen({ setup: true });
    return null;
  }
  try {
    return await api.get("/api/auth/me", { cache: false });
  } catch (_error) {
    api.clearAuthTokens();
    authScreen();
    return null;
  }
}

async function boot() {
  const user = await requireOwnerLogin();
  if (!user) return;
  buildChrome(user);
  // Prime the CSRF cookie so the first POST doesn't round-trip.
  api.get("/api/csrf-token").catch(() => {});
  initWs();
  router.start();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => { boot(); });
} else {
  boot();
}
