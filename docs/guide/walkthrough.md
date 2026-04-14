# Walkthrough

This page is the long version of "first day with Proxymate." It walks you through installing the app, meeting the onboarding wizard, and understanding what each tab in the menu bar actually does — with honest notes on what to expect, what not to expect, and where the sharp edges are.

Everything here is true of the current release. If a button, toggle, or counter doesn't behave as described, it's a bug, not a feature.

## 1. Before you install

You'll need:

- **macOS 26 (Tahoe) or newer.** The binary targets macOS 26.1; older versions refuse to launch.
- **Apple Silicon.** M1 / M2 / M3 / M4. Intel is not a supported target and the DMG won't install on it.
- **An admin account** — or at least the ability to enter an admin password once when the app installs its network configuration. Proxymate does not run as root; it shells out via `osascript do shell script with administrator privileges` for the two things that legitimately need it (modifying the system proxy and trusting its CA).
- **About 150 MB of free disk.** The bundled mitmproxy sidecar alone is 88 MB because it ships with its own Python runtime.

If you're on macOS 25 or earlier, or Intel, this page will lie to you. Come back when you upgrade.

## 2. Installing

You have two paths. Pick whichever matches your mood.

### Homebrew (recommended)

If you already run Homebrew, this is the shortest route:

```bash
brew tap fabriziosalmi/proxymate
brew install --cask proxymate
```

That's it. The tap is at [github.com/fabriziosalmi/homebrew-proxymate](https://github.com/fabriziosalmi/homebrew-proxymate). Updates go through `brew upgrade --cask proxymate`.

### Direct DMG

If you'd rather download the file yourself:

1. Grab `Proxymate-0.9.48.dmg` from the [latest release](https://github.com/fabriziosalmi/proxymate/releases/latest).
2. Verify the hash before mounting — not because you don't trust me, but because this is a good habit with any app that handles your network traffic:

   ```bash
   shasum -a 256 ~/Downloads/Proxymate-0.9.48.dmg
   # should match the SHA-256 line on the release page
   ```

3. Mount, drag `Proxymate.app` to `/Applications`, eject.

Either way, the first launch is silent. The DMG is notarized by Apple and stapled, so Gatekeeper won't pop a "Cannot verify developer" dialog and you don't have to right-click → Open. It just opens.

## 3. The menu bar icon

After launch, look at the top-right of your screen. You'll see a small shield icon next to the system clock. That's the only UI surface Proxymate occupies — there is no Dock icon, no application window hanging around, no workspace clutter. The app is designed to live in the menu bar.

Clicking it opens a panel. The header of that panel is the single most important control in the app: a status line and a toggle.

- **Status line** — reads "Off" when nothing is happening, "On" when your traffic is routing through. The color follows along: gray when off, accent blue when on.
- **Toggle** — flips enable/disable. The first time you flip it on, macOS will prompt for your admin password (once; cached for ~5 minutes by the OS).

Below the header, seven tabs: **Proxies**, **Logs**, **Stats**, **Rules**, **AI**, **Cache**, **Privacy**. We'll go through each one later.

Right-clicking the menu bar icon or clicking "Quit" in the panel footer exits cleanly — it'll disable the proxy and restore your system to direct connections before the process ends. If you force-quit (⌥⌘⎋), the system proxy stays configured at a listener that no longer exists; in that case you may need to open the Proxymate panel again and toggle off, or reset the system proxy manually via System Settings → Network → Details → Proxies.

## 4. The onboarding wizard

On your very first launch, a wizard sheet appears over the menu bar panel. It has six steps, a progress bar at the top, and "Back" / "Next" buttons at the bottom. On step one, "Back" becomes "Skip for now" — you can dismiss the wizard without it flipping the "already onboarded" flag, so it'll greet you again on the next launch.

If you close the sheet via ESC or clicking outside, same thing: you're not marked onboarded. The flag flips only when you reach the last step and click **Finish** (or **Finish & Enable**). This is intentional — accidentally dismissing the wizard should never leave you with an unconfigured app.

### Step 1 — Choose a profile

Five pre-built starting points. Pick the one closest to your use case; you can switch anything later.

- **Privacy** — blocks ads, trackers, crypto miners; strips tracking headers; enables DNS-over-HTTPS through Cloudflare. This is the default selection.
- **Developer** — minimal blocking (just malware and crypto miners). Turns on the L1/L2 cache and the AI token tracker. Good if you're using Claude Code / Cursor / etc. and want to see tokens fly by.
- **Enterprise** — blocks malware, phishing, ads, crypto miners, and TOR exits. Whitelists the three RFC1918 ranges so your corporate LAN, Tailscale, or office VPN keeps working.
- **Family Safety** — the "everything blocked" option: adult, malware, phishing, ads, telemetry. Maximum noise in the Logs tab, maximum peace of mind.
- **Minimal** — nothing is pre-enabled. You configure every rule yourself. If you pick this, a note appears under the profile list explicitly saying so, because the later "Ready to Go" step can otherwise feel misleading.

### Step 2 — Upstream proxy

This is the one step that reliably trips people up, so read it twice.

- **If you have no existing proxy**, leave "I have an upstream proxy" **off**. Proxymate will use its bundled Local Squid (a full Squid binary shipped inside the app, not a system-level install) as the upstream. Your traffic flows: _app → Proxymate listener → bundled Squid → internet_. Requests arrive at the far end with your normal IP and your normal TLS — Proxymate is filtering and logging, not tunneling.
- **If you already run a proxy** — corporate web gateway, Tailscale exit, home VPN proxy — toggle it on and fill in host + port. The app validates the input inline: if you type letters in the port field or a hostname with shell metacharacters, the Next button is disabled and you'll see an orange hint explaining why.

There is no "direct / no upstream" mode in the current architecture. Every request goes through _something_ — either the bundled Squid or your own. That's why the validator is strict: the configured upstream gets used, period.

### Step 3 — Privacy level

A slider with three positions:

- **Minimal** — DNT and Sec-GPC headers injected on every request. That's it.
- **Moderate** — everything above, plus tracking cookies (`_ga`, `_fbp`, `utma`, etc.) filtered out of every outbound Cookie header.
- **Maximum** — everything above, plus User-Agent rewritten to a stock value, Referer reduced to origin-only, and ETag stripped to defeat supercookies.

Each item on the checklist has a green tick or a gray circle depending on where the slider is. A DoH toggle lives under the slider — when on, Proxymate resolves DNS over HTTPS through Cloudflare (one.one.one.one) instead of your ISP's resolver. This is separate from the privacy level and purely additive.

### Step 4 — AI observability

A single toggle: "Enable AI tracking". When on, Proxymate detects outbound requests to the 11 built-in AI providers (OpenAI, Anthropic, Google, Mistral, Cohere, Together, Groq, DeepSeek, Perplexity, xAI, Ollama), counts tokens from response bodies, estimates cost using a built-in pricing table, and identifies which of the common AI coding agents (Claude Code, Cursor, Windsurf, Aider, Copilot, Codex CLI) sent the request. It also watches for runaway loops — agents stuck in an identical rapid-fire retry.

If you never use AI tools, leave this off. It has no effect on non-AI traffic and won't block anything unless you later configure a budget.

### Step 5 — HTTPS inspection (CA install)

This is the step that asks for your admin password. It's optional — you can skip it and everything except deep HTTPS inspection will still work.

When you click **Install Certificate**, the app:

1. Generates a 2048-bit RSA root CA on your machine, AES-256 encrypted with a random passphrase stored in your login Keychain.
2. Prompts `security add-trusted-cert` via osascript; you enter your admin password; the CA joins the system trust store.
3. Polls macOS for up to 15 seconds to confirm the trust actually took. Only then does the UI show "Certificate installed & trusted" in green. If you cancel the admin prompt, you get a clear error instead of a false green checkmark (this was a bug pre-0.9.49 — now fixed).

You can always revisit this step from **Preferences → Privacy → MITM** and install or remove the CA later. Removal is behind a confirmation dialog that spells out what breaks when the CA is gone.

### Step 6 — Summary & finish

A single card recapping your choices:

- Profile name
- Upstream (either `host:port` or "Direct")
- Privacy level (Minimal / Moderate / Maximum)
- DNS-over-HTTPS on/off
- AI tracking on/off

Under the summary, a toggle labelled **Enable the proxy now** (on by default). If you leave it on, clicking **Finish & Enable** does three things in order: persist your settings, mark you as onboarded, and call `state.enable()` to actually flip the proxy on. The admin password prompt for the system-proxy change is shown here, not earlier. If you uncheck the toggle, the button becomes **Finish** and you land on the main panel with the proxy still off — click the header toggle whenever you're ready.

## 5. Enabling the proxy

When you flip the main toggle on (from anywhere — wizard finish, header toggle, keyboard shortcut), a specific chain of things happens. Knowing it helps when something doesn't look right.

1. **Validation.** The app checks you have a selected upstream and that its host/port make sense. If not, you get a warning log and the toggle stays off.
2. **Idempotent pre-check.** The app reads the current system proxy via `SCDynamicStore`. If it's already correctly configured for your listener, the privileged `networksetup` call is skipped entirely — no extra admin prompt. This is how wake-from-sleep and Wi-Fi transitions no longer re-prompt for your password.
3. **Sidecar auto-start.** If your selected upstream is one of the bundled ones (`127.0.0.1:3128` for Squid), the embedded sidecar is launched now. It uses a temp directory under `/tmp/proxymate-squid` and binds only to loopback. If you already run your own Squid on 3128, the app reuses yours silently.
4. **Local listener.** A new `NWListener` binds to a random loopback port (usually 5 digits). This is where your browser, your CLI tools, and every other app will send traffic.
5. **System proxy.** `networksetup -setwebproxy` + `-setsecurewebproxy` configure every active network service (Wi-Fi, Ethernet, Tailscale, Thunderbolt Bridge…) to route through that loopback port. The bypass list — localhost, `*.local`, RFC1918, link-local — is set at the same time.
6. **Post-apply verification.** The app reads back the system proxy via `SCDynamicStore` again and confirms the values match the target. If they don't, you get a real error in the Logs tab ("System proxy not applied") instead of a silent lie. This safeguard exists because the macOS 26 authorization APIs can return success while doing nothing — one of the bugs that triggered the first full audit of this app.
7. **PAC + SOCKS5 + metrics.** Any of these that are enabled get their listeners started in parallel. If a port is already bound, the listener logs the failure explicitly; the toggle for that feature won't silently stay on while nothing's actually listening.

After all that, the header toggle turns blue, the status reads "On", and the Logs tab starts filling up within seconds as apps open their first TLS connections.

If anything went wrong, the Logs tab will tell you — every failure surfaces either as `.error` or `.warn`, never as silent no-op.

---

_This is the end of Batch 1 — the rest of this walkthrough (the seven tabs + troubleshooting) is coming next. Continue from [Tab: Proxies](#tab-proxies) once it lands._
