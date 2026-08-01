import { create } from 'zustand'

const PALETTE_KEY = 'heimdall_palette'

const initial = localStorage.getItem(PALETTE_KEY) || 'amber'
// Set at module-load time (before React ever renders), same reasoning as
// authStore's refresh-token read — index.css's [data-palette] selectors
// need this in place before first paint, or the page briefly flashes the
// @theme default (Amber CRT) before the stored choice applies.
document.documentElement.setAttribute('data-palette', initial)

export const useThemeStore = create((set) => ({
  palette: initial,

  setPalette(palette) {
    localStorage.setItem(PALETTE_KEY, palette)
    document.documentElement.setAttribute('data-palette', palette)
    set({ palette })
  },
}))
