import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthGuard } from './AuthGuard'
import { Shell } from './Shell'
import { LoginPage } from './pages/LoginPage'
import { PlaceholderPage } from './pages/PlaceholderPage'
import { DashboardPage } from './pages/DashboardPage'

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
              <Route path="/devices" element={<PlaceholderPage title="Devices" />} />
              <Route path="/devices/:mac" element={<PlaceholderPage title="Device Detail" />} />
              <Route path="/alerts" element={<PlaceholderPage title="Alerts" />} />
              <Route path="/ports" element={<PlaceholderPage title="Ports" />} />
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
