import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

const MOBILE_QUERY = '(max-width: 768px)'

function viewportPrefersMobile() {
  return window.matchMedia(MOBILE_QUERY).matches
}

/** ?mobile=1 / ?mobile=0 force a layout; otherwise auto-detect from viewport
 * width so opening the site on a phone works without knowing the query trick. */
export function useLayoutMode() {
  const [searchParams] = useSearchParams()
  const override = searchParams.get('mobile')
  const [viewportMobile, setViewportMobile] = useState(viewportPrefersMobile)

  useEffect(() => {
    const mql = window.matchMedia(MOBILE_QUERY)
    const onChange = (e) => setViewportMobile(e.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  if (override === '1') return 'mobile'
  if (override === '0') return 'desktop'
  return viewportMobile ? 'mobile' : 'desktop'
}
