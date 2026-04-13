import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import HeroExtras from './components/HeroExtras.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'home-hero-after': () => h(HeroExtras),
    })
  },
}
