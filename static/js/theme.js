/* Theme: light, dark or automatic. Loaded in <head> so the page never flashes the wrong colours. */
(function () {
  "use strict";
  var KEY = "sh-theme", root = document.documentElement;
  var ICONS = { light: "☀️", dark: "🌙", auto: "🖥️" };
  var NAMES = { light: "Light", dark: "Dark", auto: "Automatic" };
  function saved() { try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : "auto"; } catch (e) { return "auto"; } }
  function apply(mode) {
    var dark = mode === "dark" || (mode === "auto" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    root.setAttribute("data-theme", dark ? "dark" : "light");
    root.setAttribute("data-theme-mode", mode);
  }
  apply(saved());
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    var onChange = function () { if (saved() === "auto") apply("auto"); };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
  }
  function paint() {
    var mode = saved();
    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), function (btn) {
      btn.textContent = ICONS[mode];
      btn.title = "Theme: " + NAMES[mode] + " (click to change)";
      btn.setAttribute("aria-label", "Theme: " + NAMES[mode] + ". Click to change.");
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    paint();
    document.addEventListener("click", function (e) {
      var btn = e.target.closest && e.target.closest("[data-theme-toggle]");
      if (!btn) return;
      var next = { light: "dark", dark: "auto", auto: "light" }[saved()];
      try { localStorage.setItem(KEY, next); } catch (err) { /* private mode: still apply for this page */ }
      apply(next);
      var mode = next;
      Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), function (b) {
        b.textContent = ICONS[mode]; b.title = "Theme: " + NAMES[mode] + " (click to change)";
        b.setAttribute("aria-label", "Theme: " + NAMES[mode] + ". Click to change.");
      });
    });
  });
})();
