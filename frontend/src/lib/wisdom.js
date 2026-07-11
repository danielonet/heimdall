import { WISDOM_PHRASES } from '../config/wisdomPhrases'

const STORAGE_KEY = 'heimdall_wisdom_index'

/** Cycles through WISDOM_PHRASES in order (not random) so the login screen
 * shows a new one on every visit, wrapping back to the start once every
 * phrase has been shown. Position persists across sessions via localStorage. */
export function nextWisdomPhrase() {
  const stored = Number(localStorage.getItem(STORAGE_KEY))
  const index = Number.isInteger(stored) && stored >= 0 ? stored % WISDOM_PHRASES.length : 0
  localStorage.setItem(STORAGE_KEY, String((index + 1) % WISDOM_PHRASES.length))
  return WISDOM_PHRASES[index]
}
