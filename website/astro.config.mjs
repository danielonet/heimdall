import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://heimdall.it.com',
  trailingSlash: 'always',
  build: { format: 'directory' },
  integrations: [
    starlight({
      title: 'Heimdall manual',
      description: 'How to use the Heimdall dashboard.',
      favicon: '/favicon.svg',
      // The product is dark-only; the palette toggle replaces Starlight's theme select.
      components: { ThemeSelect: './src/components/PaletteToggle.astro', SiteTitle: './src/components/ManualTitle.astro' },
      customCss: ['@fontsource/jetbrains-mono/400.css', '@fontsource/jetbrains-mono/700.css', '@fontsource/rajdhani/600.css', '@fontsource/rajdhani/700.css', './src/styles/tokens.css', './src/styles/starlight.css'],
      head: [{ tag: 'script', content: "try{var p=localStorage.getItem('heimdall_palette');if(p==='slate')document.documentElement.setAttribute('data-palette','slate')}catch(e){}" }],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/danielonet/heimdall' }],
      pagination: true,
      sidebar: [
        { label: 'Start', items: ['manual', 'manual/first-login', 'manual/mobile'] },
        { label: 'Pages', items: ['manual/dashboard', 'manual/network-map', 'manual/devices', 'manual/alerts', 'manual/threats', 'manual/ports', 'manual/wifi-scan', 'manual/rules', 'manual/reports', 'manual/equipment', 'manual/settings'] },
        { label: 'Help', items: ['manual/troubleshooting', 'manual/faq', 'manual/glossary'] },
      ],
    }),
    sitemap(),
  ],
});
