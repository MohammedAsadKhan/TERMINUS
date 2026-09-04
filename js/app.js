/* ==========================================================================
   Agentic SOC — app.js (shared across all pages)
   1. Foundation init
   2. Shared nav: highlight active page by filename
   3. Scroll reveal (subtle, IntersectionObserver)
   ========================================================================== */

/* --- 1. Foundation init -------------------------------------------------- */
$(document).foundation();

/* --- 2. Shared nav active state ------------------------------------------ */
(function () {
  "use strict";
  var file = window.location.pathname.split("/").pop() || "index.html";
  var links = document.querySelectorAll("[data-nav] a");
  for (var i = 0; i < links.length; i++) {
    var href = links[i].getAttribute("href");
    if (href === file) {
      links[i].classList.add("is-active");
      links[i].setAttribute("aria-current", "page");
    }
  }
})();

/* --- 3. Scroll reveal ----------------------------------------------------- */
(function () {
  "use strict";
  var els = document.querySelectorAll(".reveal-on-scroll");
  if (!els.length) { return; }
  if (!("IntersectionObserver" in window)) {
    for (var i = 0; i < els.length; i++) { els[i].classList.add("is-visible"); }
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });
  for (var i = 0; i < els.length; i++) { io.observe(els[i]); }
})();
