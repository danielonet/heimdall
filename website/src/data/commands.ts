import type { Tab } from '../components/Terminal.astro';

const script = (tier: string): Tab => ({
  label: tier,
  lines: [{ cmd: `curl -fsSL https://heimdall.it.com/install.sh | bash -s -- --tier=${tier}` }],
});

export const debLines = [
  { cmd: 'curl -fsSLO https://heimdall.it.com/download/heimdall_all.deb' },
  { cmd: 'sudo apt install ./heimdall_all.deb', note: 'installs Docker and the compose plugin if missing' },
  { cmd: 'sudo heimdall setup', note: 'tier, router, your dashboard user name and password; generates this machine’s secrets' },
  { cmd: 'sudo heimdall start', note: 'pulls the images; starts now and at every boot' },
];

export const homeTabs: Tab[] = [script('minimal'), script('intermediate'), script('full'), { label: 'Debian / Ubuntu .deb', lines: debLines }];

export const installTabs: Tab[] = [
  script('intermediate'),
  { label: 'Debian / Ubuntu .deb', lines: debLines },
  { label: 'By hand', lines: [
    { cmd: 'curl -fsSLO https://heimdall.it.com/download/heimdall-bundle.tar.gz' },
    { cmd: 'curl -fsSLO https://heimdall.it.com/download/heimdall-bundle.tar.gz.sha256' },
    { cmd: 'sha256sum -c heimdall-bundle.tar.gz.sha256 && tar xzf heimdall-bundle.tar.gz && cd heimdall' },
    { cmd: './setup.sh' },
    { cmd: 'docker compose pull && docker compose up -d' },
  ] },
];
