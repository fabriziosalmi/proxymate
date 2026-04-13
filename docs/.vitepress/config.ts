import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Proxymate',
  description: 'A privacy-first macOS proxy with WAF, MITM, and AI agent controls.',
  base: '/proxymate/',
  cleanUrls: true,
  lastUpdated: true,
  appearance: 'dark',

  head: [
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
          ],
        },
        {
          text: 'Capabilities',
          items: [
            { text: 'Features overview', link: '/guide/features' },
            { text: 'Security model', link: '/guide/security' },
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
      message: 'Zero telemetry. Apple-frameworks only. Audited.',
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
