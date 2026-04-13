<script setup lang="ts">
// Trust strip below the hero: small, monospace-ish, uppercase SF Text feel.
// Communicates what Proxymate is NOT (telemetry, cloud, subscription)
// in three crisp bullets — reinforces the privacy positioning.
const badges = [
  { icon: '🛡️', label: 'Zero telemetry' },
  { icon: '💎', label: 'Apple frameworks only' },
  { icon: '✅', label: 'Notarized for macOS 26' },
]
</script>

<template>
  <div class="hero-extras">
    <div class="trust-strip">
      <div v-for="b in badges" :key="b.label" class="badge">
        <span class="badge-icon">{{ b.icon }}</span>
        <span class="badge-label">{{ b.label }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hero-extras {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 32px 48px;
}

.trust-strip {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: center;
  margin-top: 8px;
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 980px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: -0.005em;
  color: var(--vp-c-text-2);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
}

.badge-icon {
  font-size: 16px;
  line-height: 1;
}

@media (max-width: 640px) {
  .trust-strip {
    gap: 8px;
  }
  .badge {
    font-size: 12px;
    padding: 6px 12px;
  }
}
</style>
