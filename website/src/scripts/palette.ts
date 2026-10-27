// Palette toggle shared by the site and the manual. Same attribute and key as the product (themeStore.js).
const root = document.documentElement;
const read = (): string | null => { try { return localStorage.getItem('heimdall_palette'); } catch { return null; } };
const write = (p: string): void => { try { localStorage.setItem('heimdall_palette', p); } catch { /* private mode */ } };

function apply(p: 'amber' | 'slate'): void {
  root.setAttribute('data-palette', p);
  write(p);
  document.querySelectorAll<HTMLElement>('[data-palette-toggle]').forEach((b) => { b.textContent = p === 'amber' ? '◐ Slate' : '◐ Amber'; });
}

apply(read() === 'slate' ? 'slate' : 'amber');
document.addEventListener('click', (e) => {
  if ((e.target as Element).closest('[data-palette-toggle]')) apply(root.getAttribute('data-palette') === 'amber' ? 'slate' : 'amber');
});
