export function MacAddress({ mac, vendor }) {
  return (
    <span className="font-mono text-text-secondary" title={vendor || undefined}>
      {mac}
    </span>
  )
}
