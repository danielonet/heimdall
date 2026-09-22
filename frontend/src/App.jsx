import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthGuard } from './AuthGuard'
import { Shell } from './Shell'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { NetworkMapPage } from './pages/NetworkMapPage'
import { DevicesPage } from './pages/DevicesPage'
import { DeviceDetailPage } from './pages/DeviceDetailPage'
import { AlertsPage } from './pages/AlertsPage'
import { PortsPage } from './pages/PortsPage'
import { WifiScanPage } from './pages/WifiScanPage'
import { ThreatsPage } from './pages/ThreatsPage'
import { RulesPage } from './pages/RulesPage'
import { ReportsPage } from './pages/ReportsPage'
import { SettingsPage } from './pages/SettingsPage'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 5000 } },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthGuard>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<Shell />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/map" element={<NetworkMapPage />} />
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/devices/:mac" element={<DeviceDetailPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/ports" element={<PortsPage />} />
              <Route path="/wifi" element={<WifiScanPage />} />
              <Route path="/threats" element={<ThreatsPage />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              {/* Notifications is now a section of Settings, not its own
                  page — redirect any old link/bookmark instead of a 404. */}
              <Route path="/notifications" element={<Navigate to="/settings" replace />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Routes>
        </AuthGuard>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
