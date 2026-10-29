import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useRouterCatalog() {
  return useQuery({
    queryKey: ['routers', 'catalog'],
    queryFn: () => apiJson('/routers/catalog'),
    select: (data) => data.routers,
    staleTime: Infinity,
  })
}

export function useSelectedRouters() {
  return useQuery({
    queryKey: ['routers', 'selected'],
    queryFn: () => apiJson('/routers'),
    select: (data) => data.selected,
    refetchInterval: 15000,
  })
}

// Sagemcom and MiWiFi predate the router_profiles table: their login lives in
// the Settings columns/secret files and PATCH /settings hot-reloads the live
// adapter, so those two go through it. Every other router uses /routers/<id>.
function settingsBody(spec, { host, username, password }) {
  const body = {}
  if (spec.id === 'sagemcom-xmo') {
    body.router_username = username
    if (password) body.router_password = password
  } else {
    body.miwifi_ip = host
    if (password) body.miwifi_password = password
  }
  return body
}

export function useSaveRouter() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ spec, ...creds }) =>
      spec.credential_store === 'settings'
        ? apiJson('/settings', { method: 'PATCH', body: JSON.stringify(settingsBody(spec, creds)) })
        : apiJson(`/routers/${spec.id}`, {
            method: 'PUT',
            body: JSON.stringify({ host: creds.host, username: creds.username, password: creds.password || undefined }),
          }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['routers', 'selected'] })
      qc.invalidateQueries({ queryKey: ['settings'] })
    },
  })
}

export function useRemoveRouter() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ spec }) =>
      spec.credential_store === 'settings'
        ? apiJson('/settings', { method: 'PATCH', body: JSON.stringify({ miwifi_ip: '' }) })
        : apiJson(`/routers/${spec.id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['routers', 'selected'] })
      qc.invalidateQueries({ queryKey: ['settings'] })
    },
  })
}

// Tries the saved login for real: { ok, model, firmware, devices } or { ok: false, error }.
export function useTestRouter() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ spec }) => apiJson(`/routers/${spec.id}/test`, { method: 'POST' }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['routers', 'selected'] }),
  })
}
