import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthGuard } from './AuthGuard'
import { Shell } from './Shell'
import { LoginPage } from './pages/LoginPage'
import { PlaceholderPage } from './pages/PlaceholderPage'
import { DashboardPage } from './pages/DashboardPage'
import { DevicesPage } from './pages/DevicesPage'
import { DeviceDetailPage } from './pages/DeviceDetailPage'
import { AlertsPage } from './pages/AlertsPage'
import { PortsPage } from './pages/PortsPage'

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
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/devices/:mac" element={<DeviceDetailPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/ports" element={<PortsPage />} />
              <Route path="/threats" element={<PlaceholderPage title="Threat Intel" />} />
              <Route path="/rules" element={<PlaceholderPage title="Rules" />} />
              <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
            </Route>
          </Routes>
        </AuthGuard>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
