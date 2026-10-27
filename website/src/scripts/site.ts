// Tabs and copy buttons for the terminal blocks.
document.addEventListener('click', (e) => {
  const target = e.target as Element;
  const tab = target.closest<HTMLElement>('[role=tab]');
  if (tab) {
    const group = tab.closest('[data-tabs]');
    group?.querySelectorAll<HTMLElement>('[role=tab]').forEach((b) => {
      const on = b === tab;
      b.setAttribute('aria-selected', String(on));
      const panel = document.getElementById(b.getAttribute('aria-controls') ?? '');
      if (panel) panel.hidden = !on;
    });
  }
  const copy = target.closest<HTMLButtonElement>('.copy');
  if (copy) {
    const text = copy.getAttribute('data-text') ?? '';
    navigator.clipboard.writeText(text).then(
      () => { copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy'; }, 1500); },
      () => { copy.textContent = 'Select + Ctrl-C'; },
    );
  }
});

// Equipment table filter.
document.querySelectorAll<HTMLButtonElement>('[data-filter]').forEach((b) => {
  b.addEventListener('click', () => {
    const f = b.dataset.filter ?? 'all';
    document.querySelectorAll<HTMLElement>('#eq tbody tr').forEach((r) => { r.hidden = f !== 'all' && !(r.dataset.k ?? '').split(' ').includes(f); });
    document.querySelectorAll<HTMLElement>('[data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  });
});
