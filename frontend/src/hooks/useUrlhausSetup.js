import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

// The URLhaus feed needs a free abuse.ch Auth-Key. These mutations save /
// remove it (the backend writes it to the secrets file and refreshes the feed
// immediately) or load a CSV the user already has, for people who want to
// create the key later. Each returns the fresh { feeds } payload, so the
// threat-feeds query is updated without waiting for the next poll.
function useFeedMutation(mutationFn) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn,
    onSuccess: (data) => qc.setQueryData(['threat-feeds'], { feeds: data.feeds }),
  })
}

export function useSaveUrlhausKey() {
  return useFeedMutation((authKey) =>
    apiJson('/threats/feeds/urlhaus/key', {
      method: 'PUT',
      body: JSON.stringify({ auth_key: authKey }),
    }),
  )
}

export function useRemoveUrlhausKey() {
  return useFeedMutation(() => apiJson('/threats/feeds/urlhaus/key', { method: 'DELETE' }))
}

export function useImportUrlhausCsv() {
  return useFeedMutation((file) => {
    const form = new FormData()
    form.append('file', file)
    return apiJson('/threats/feeds/urlhaus/import', { method: 'POST', body: form })
  })
}
