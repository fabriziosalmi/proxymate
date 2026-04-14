---
layout: home
title: Proxymate — Privacy-first macOS proxy

hero:
  name: "Proxymate"
  text: "Your Mac. Your traffic. Your rules."
  tagline: "A local HTTP/HTTPS proxy with a built-in WAF, MITM interception, AI agent controls, and zero telemetry. Native to macOS, notarized for distribution."
  image:
    src: /hero.svg
    alt: Proxymate menu bar app with traffic logs
  actions:
    - theme: brand
      text: Install
      link: /guide/installation
    - theme: alt
      text: What it does
      link: /guide/features
    - theme: alt
      text: View on GitHub
      link: https://github.com/fabriziosalmi/proxymate

features:
  - icon:
      src: /icons/shield.svg
      alt: Shield
    title: Web Application Firewall
    details: Block domains, IPs, and content patterns with O(1) rule matching. Ships with curated lists (Steven Black, NoCoin, URLhaus, TOR exits) totalling ~90K entries.
  - icon:
      src: /icons/lock.svg
      alt: Lock
    title: Transparent TLS Interception
    details: Per-installation root CA stored AES-encrypted, Keychain-bound. Forges leaf certs on demand via an embedded mitmproxy sidecar. Auto-excludes pinned apps.
  - icon:
      src: /icons/brain.svg
      alt: AI brain
    title: AI Agent Controls
    details: Detects Claude Code, Cursor, Codex and every major model API. Tracks tokens, estimates cost, blocks loops and model budget overruns.
  - icon:
      src: /icons/eye.svg
      alt: Privacy
    title: Privacy Header Rewriting
    details: Strip trackers, inject DNT + GPC, rewrite User-Agent, filter tracking cookies. Per-host policy, configurable in seconds.
  - icon:
      src: /icons/bolt.svg
      alt: Fast
    title: Sub-millisecond Overhead
    details: Aho-Corasick for content matching, connection pool with LRU keepalive, in-process L1 + SQLite L2 cache. Benchmarked at <1ms added latency.
  - icon:
      src: /icons/target.svg
      alt: Threat detection
    title: Threat Detection
    details: Beaconing heuristic (periodic callback patterns), C2 framework fingerprints (Cobalt Strike, Sliver, Mythic), exfiltration pattern packs for PII and credentials.
  - icon:
      src: /icons/compass.svg
      alt: Routing
    title: Multi-Upstream Pool
    details: Round-robin, least-connections, weighted, geo, latency-based routing across multiple upstream proxies. Health checks with circuit breaker.
  - icon:
      src: /icons/waves.svg
      alt: Protocols
    title: Everything Else You'd Expect
    details: SOCKS5 listener, PAC server with smart bypass, DNS-over-HTTPS, Prometheus metrics, webhooks, iCloud sync of your rule sets.
---
