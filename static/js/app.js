/* Sentry Hub front-end behaviour. No inline scripts are used (strict Content-Security-Policy). */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ---- toasts ---- */
  function dismiss(toast) {
    toast.classList.add("leaving");
    setTimeout(function () { toast.remove(); }, 320);
  }
  function showToast(message, kind) {
    var box = $("#toasts");
    if (!box) return;
    var t = document.createElement("div");
    t.className = "toast toast-" + (kind || "info");
    t.setAttribute("role", "status");
    t.textContent = message;
    box.appendChild(t);
    setTimeout(function () { dismiss(t); }, 5000);
  }
  $$(".toast").forEach(function (t, i) { setTimeout(function () { dismiss(t); }, 5000 + i * 400); });

  /* ---- show / hide password ---- */
  $$("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = btn.parentElement.querySelector("input");
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  /* ---- password strength meter ---- */
  var strengthInput = $("[data-strength-input]");
  if (strengthInput) {
    var bar = $("[data-strength-bar]"), text = $("[data-strength-text]");
    var labels = ["At least 10 characters, with a letter and a number.", "Too weak", "Getting there", "Good", "Strong"];
    strengthInput.addEventListener("input", function () {
      var v = strengthInput.value, score = 0;
      if (v.length >= 10) score++;
      if (/[A-Za-z]/.test(v) && /\d/.test(v)) score++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 16) score++;
      if (!v) score = 0;
      bar.dataset.level = score;
      text.textContent = labels[score];
    });
  }

  /* ---- one-time code input: digits only, shown as "123 456" ---- */
  var code = $("[data-code-input]");
  if (code) {
    code.addEventListener("input", function () {
      var d = code.value.replace(/\D/g, "").slice(0, 6);
      code.value = d.length > 3 ? d.slice(0, 3) + " " + d.slice(3) : d;
    });
  }

  /* ---- resend countdown ---- */
  var resend = $("[data-resend]");
  if (resend) {
    var wait = parseInt(resend.dataset.wait || "0", 10);
    if (wait > 0) {
      resend.disabled = true;
      var tick = setInterval(function () {
        wait -= 1;
        if (wait <= 0) {
          clearInterval(tick);
          resend.disabled = false;
          resend.textContent = "Resend code";
        } else {
          resend.textContent = "Resend in " + wait + "s";
        }
      }, 1000);
      resend.textContent = "Resend in " + wait + "s";
    }
  }

  /* ---- confirm dialog for forms with data-confirm ---- */
  var dialog = $("#confirm-dialog");
  $$("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!dialog || typeof dialog.showModal !== "function") {
        if (!window.confirm(form.dataset.confirm)) e.preventDefault();
        return;
      }
      e.preventDefault();
      $("#confirm-title").textContent = form.dataset.confirm;
      $("#confirm-text").textContent = form.dataset.confirmText || "";
      $("#confirm-ok").textContent = "Delete";
      dialog.returnValue = "";
      dialog.showModal();
      dialog.addEventListener("close", function onClose() {
        dialog.removeEventListener("close", onClose);
        if (dialog.returnValue === "ok") form.submit();
      });
    });
  });

  /* ---- mobile sidebar ---- */
  var menu = $("[data-menu]"), sidebar = $("#sidebar");
  if (menu && sidebar) {
    menu.addEventListener("click", function () { sidebar.classList.toggle("open"); });
    $$(".side-nav a").forEach(function (a) { a.addEventListener("click", function () { sidebar.classList.remove("open"); }); });
    document.addEventListener("click", function (e) {
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && !menu.contains(e.target)) sidebar.classList.remove("open");
    });
  }

  /* ---- table search + status filter ---- */
  function applyFilters(table) {
    var input = $('[data-filter-input="' + table.id + '"]');
    var q = input ? input.value.trim().toLowerCase() : "";
    var activeBtn = $("[data-status-filter].active");
    var status = table.id === "admin-table" && activeBtn ? activeBtn.dataset.statusFilter : "all";
    var shown = 0;
    $$("tbody tr", table).forEach(function (row) {
      var ok = (!q || (row.dataset.search || "").indexOf(q) !== -1) && (status === "all" || row.dataset.status === status);
      row.hidden = !ok;
      if (ok) shown++;
    });
    var empty = table.closest(".panel").querySelector("[data-empty]");
    if (empty) empty.hidden = shown !== 0;
  }
  $$("[data-filter-input]").forEach(function (input) {
    var table = document.getElementById(input.dataset.filterInput);
    if (table) input.addEventListener("input", function () { applyFilters(table); });
  });
  $$("[data-status-filter]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      $$("[data-status-filter]").forEach(function (b) { b.classList.toggle("active", b === btn); });
      var table = $("#admin-table");
      if (table) applyFilters(table);
    });
  });

  /* ---- reveal the full salt / hash on click ---- */
  $$("code.secret").forEach(function (el) {
    var short = el.textContent;
    function toggle() {
      var open = el.classList.toggle("open");
      el.textContent = open ? el.dataset.secret : short;
      el.title = open ? "Click to hide" : "Click to reveal";
    }
    el.addEventListener("click", toggle);
    el.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  });

  /* ---- backup button ---- */
  var backupBtn = $("#backup-btn");
  if (backupBtn) {
    var label = $(".btn-label", backupBtn), spinner = $(".spinner", backupBtn);
    backupBtn.addEventListener("click", function () {
      var token = ($('meta[name="csrf-token"]') || {}).content || "";
      backupBtn.disabled = true;
      label.textContent = "Backing up…";
      spinner.hidden = false;
      fetch(backupBtn.dataset.url, { method: "POST", headers: { "X-CSRF-Token": token, "Accept": "application/json" }, credentials: "same-origin" })
        .then(function (res) {
          return res.json().catch(function () { return { ok: false, message: "Backup failed (server error " + res.status + ")" }; });
        })
        .then(function (data) {
          showToast(data.message, data.ok ? "success" : "error");
          if (data.ok) {
            var last = $("#backup-last");
            if (last) last.textContent = data.when;
          } else {
            setTimeout(function () { window.location.reload(); }, 2500);
          }
        })
        .catch(function () { showToast("Backup failed: could not reach the server.", "error"); })
        .then(function () {
          backupBtn.disabled = false;
          label.textContent = "Back up now";
          spinner.hidden = true;
        });
    });
  }
})();
