<script setup lang="ts">
// Trust strip below the hero: small, glass-card badges that reinforce the
// privacy positioning in three crisp claims. SVGs over emoji — emoji render
// inconsistently across platforms and break the Apple-native feel.
</script>

<template>
  <div class="hero-extras">
    <div class="trust-strip">
      <div class="badge">
        <svg class="badge-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M2 12 Q6 5 12 5 T22 12 Q18 19 12 19 T2 12 Z" opacity="0.55"/>
          <circle cx="12" cy="12" r="3" opacity="0.55"/>
          <path d="M3 3 L21 21"/>
        </svg>
        <span>Zero telemetry</span>
      </div>

      <div class="badge">
        <svg class="badge-icon" width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <path d="M16.5 2 a4.5 4 0 0 0 -3.5 2 a4 4 0 0 0 -0.9 2.5 a4 4 0 0 0 2.8 -1.3 a4 4 0 0 0 1.6 -3.2 Z"/>
          <path d="M19 15.6 a6 6 0 0 1 2 -4.3 a4.8 4.8 0 0 0 -3.9 -2.3 c-1.6 0 -2.4 0.9 -4 0.9 c-1.6 0 -2.6 -0.9 -4.3 -0.9 c-2.2 0 -4.6 1.4 -4.6 5.2 c0 3.3 3 8.6 5 8.6 c1.3 0 1.7 -0.8 3.8 -0.8 c2.1 0 2.4 0.8 3.8 0.8 c1.8 0 3.6 -3.1 4.6 -5.2 a6 6 0 0 1 -2.4 -2 Z"/>
        </svg>
        <span>Apple frameworks only</span>
      </div>

      <div class="badge">
        <svg class="badge-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 2 L14.5 4 L18 3.5 L19 7 L22 9 L20.5 12 L22 15 L19 17 L18 20.5 L14.5 20 L12 22 L9.5 20 L6 20.5 L5 17 L2 15 L3.5 12 L2 9 L5 7 L6 3.5 L9.5 4 Z"/>
          <path d="M9 12 L11 14 L15 10"/>
        </svg>
        <span>Notarized for macOS 26</span>
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
  flex-shrink: 0;
  color: var(--vp-c-brand-1);
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
