/* Mockup behaviour only: palette toggle, tabs, copy buttons.
   The palette key and attribute match the product (themeStore.js). */
(function () {
  var root = document.documentElement;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
  function setPalette(p) { root.setAttribute('data-palette', p); store('heimdall_palette', p); var b = document.querySelector('.toggle'); if (b) b.textContent = p === 'amber' ? '◐ Slate' : '◐ Amber'; }
  setPalette(store('heimdall_palette') === 'slate' ? 'slate' : 'amber');
  document.addEventListener('click', function (e) {
    var t = e.target.closest('.toggle'); if (t) setPalette(root.getAttribute('data-palette') === 'amber' ? 'slate' : 'amber');
    var tab = e.target.closest('[role=tab]');
    if (tab) {
      var list = tab.parentElement; list.querySelectorAll('[role=tab]').forEach(function (b) {
        var on = b === tab; b.setAttribute('aria-selected', on);
        var p = document.getElementById(b.getAttribute('aria-controls')); if (p) p.hidden = !on;
      });
    }
    var c = e.target.closest('.copy');
    if (c) {
      var pre = c.parentElement.querySelector('pre'); var text = pre.innerText.replace(/^\$ /gm, '').replace(/\s+#.*$/gm, '').trim();
      (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(function () { c.textContent = 'Copied'; setTimeout(function () { c.textContent = 'Copy'; }, 1500); }, function () { c.textContent = 'Select + Ctrl-C'; });
    }
  });
})();
