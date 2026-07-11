import { useLayoutMode } from './hooks/useLayoutMode'
import { DesktopShell } from './layouts/desktop/DesktopShell'
import { MobileShell } from './layouts/mobile/MobileShell'

export function Shell() {
  const mode = useLayoutMode()
  return mode === 'mobile' ? <MobileShell /> : <DesktopShell />
}
