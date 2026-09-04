import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Proxymate',
  description: 'A privacy-first macOS proxy with WAF, MITM, and AI agent controls.',
  base: '/proxymate/',
  // The hostname carries the base path on purpose: VitePress joins it with each
  // page's route, so without it every URL in the sitemap would point at a 404.
  sitemap: { hostname: 'https://fabriziosalmi.github.io/proxymate/' },
  cleanUrls: true,
  lastUpdated: true,
  appearance: 'dark',

  head: [
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/proxymate/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0A84FF' }],
    ['meta', { property: 'og:title', content: 'Proxymate — Privacy-first macOS proxy' }],
    ['meta', { property: 'og:description', content: 'WAF, MITM, AI tracker, zero telemetry. Notarized for macOS 26.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { name: 'color-scheme', content: 'dark light' }],
  ],

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Proxymate',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Features', link: '/guide/features' },
      { text: 'Security', link: '/guide/security' },
      { text: 'Reference', link: '/reference/configuration' },
      { text: 'Releases', link: '/release-notes' },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Introduction', link: '/guide/getting-started' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'First run', link: '/guide/first-run' },
            { text: 'Walkthrough', link: '/guide/walkthrough' },
          ],
        },
        {
          text: 'Capabilities',
          items: [
            { text: 'Features overview', link: '/guide/features' },
            { text: 'Security model', link: '/guide/security' },
            { text: 'MITM & browser trust', link: '/guide/mitm-browser-trust' },
            { text: 'FAQ', link: '/guide/faq' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Configuration', link: '/reference/configuration' },
            { text: 'WAF rules', link: '/reference/rules' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/proxymate' },
    ],

    footer: {
      message: 
        'Zero telemetry. Apple-frameworks only. Audited. · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
      copyright: 'Built with care in Italy · MIT License',
    },

    search: {
      provider: 'local',
      options: {
        detailedView: true,
      },
    },

    outline: {
      level: [2, 3],
      label: 'On this page',
    },

    editLink: {
      pattern: 'https://github.com/fabriziosalmi/proxymate/edit/main/docs/:path',
      text: 'Edit this page',
    },

    docFooter: {
      prev: '← Previous',
      next: 'Next →',
    },
  },

  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
    lineNumbers: false,
  },
})
