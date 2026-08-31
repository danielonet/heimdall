import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { deviceDisplayName } from '../../lib/deviceDisplay'
import { MAP_CENTER, TIER_RADIUS, OUTER_RADIUS } from '../../lib/networkMapLayout'

const { x: CX, y: CY } = MAP_CENTER

// Node/bridge color per status — all live theme tokens (var(--color-*)) so
// the map re-colors with the Slate SOC / Amber CRT toggle like everything
// else in the app, never a hardcoded hex.
const STATUS_COLOR = {
  critical: 'var(--color-accent-red)',
  blocked: 'var(--color-accent-red)',
  warning: 'var(--color-accent-amber)',
  quarantined: 'var(--color-accent-amber)',
  online: 'var(--color-accent-green)',
  offline: 'var(--color-text-muted)',
}

function bridgeAnimClass(status) {
  if (status === 'critical') return 'network-map-anim animate-[network-map-flow_1.6s_linear_infinite]'
  if (status === 'warning') return 'network-map-anim animate-[network-map-flow_1.6s_linear_infinite]'
  if (status === 'online') return 'network-map-anim animate-[network-map-flow_2.4s_linear_infinite]'
  return ''
}

function bridgeDashArray(status) {
  if (status === 'blocked' || status === 'quarantined') return '3 5'
  if (status === 'critical' || status === 'warning' || status === 'online') return '2 7'
  return undefined
}

function nodeAnimClass(status) {
  if (status === 'critical' || status === 'blocked') {
    return 'network-map-anim animate-[network-map-pulse-crit_1.3s_ease-in-out_infinite]'
  }
  if (status === 'warning' || status === 'quarantined') {
    return 'network-map-anim animate-[network-map-pulse-warn_2.4s_ease-in-out_infinite]'
  }
  return ''
}

function nodeRadius(status) {
  return status === 'critical' || status === 'blocked' ? 6.5 : status === 'warning' || status === 'quarantined' ? 5.5 : 5
}

function Bridge({ node }) {
  const color = STATUS_COLOR[node.status]
  const mx = CX + (node.x - CX) * 0.5
  const my = CY + (node.y - CY) * 0.5
  const severed = node.status === 'blocked' || node.status === 'quarantined'
  return (
    <path
      d={`M ${CX} ${CY} Q ${mx} ${my} ${node.x} ${node.y}`}
      fill="none"
      stroke={color}
      strokeWidth={1}
      strokeDasharray={bridgeDashArray(node.status)}
      opacity={severed ? 0.3 : node.status === 'offline' ? 0.25 : node.status === 'online' ? 0.5 : 0.85}
      className={bridgeAnimClass(node.status)}
    />
  )
}

function Node({ node, onSelect, isHovered, onHover }) {
  const color = STATUS_COLOR[node.status]
  const toRight = node.x > CX
  const baseR = nodeRadius(node.status)
  const r = isHovered ? baseR + 2 : baseR
  const dim = node.status === 'offline' && !isHovered
  // nickname beats hostname beats bare MAC — same precedence as everywhere
  // else in the app (deviceDisplayName), not just a "no hostname" fallback:
  // a user-given name should win even when a router-reported hostname exists.
  const label = deviceDisplayName({ nickname: node.nickname, hostname: node.hostname, mac_address: node.mac })
  return (
    <g
      className="cursor-pointer"
      opacity={dim ? 0.4 : 1}
      onClick={() => onSelect(node.mac)}
      onMouseEnter={() => onHover(node.mac)}
      onMouseLeave={() => onHover(null)}
    >
      <title>
        {label} · {node.sector} · {node.status.toUpperCase()}
        {node.ip_address ? ` · ${node.ip_address}` : ''}
      </title>
      {/* Wider invisible hit target — the visible dots are too small to hover/click reliably. */}
      <circle cx={node.x} cy={node.y} r={14} fill="transparent" />
      {isHovered && (
        <circle cx={node.x} cy={node.y} r={r + 5} fill="none" stroke={color} strokeWidth={1} opacity={0.45} />
      )}
      <circle
        cx={node.x}
        cy={node.y}
        r={r}
        fill={node.status === 'online' || node.status === 'offline' ? 'var(--color-bg)' : color}
        stroke={color}
        strokeWidth={isHovered ? 2.5 : 1.5}
        className={nodeAnimClass(node.status)}
      />
      <text
        x={node.x + (toRight ? r + 6 : -(r + 6))}
        y={node.y + 3}
        textAnchor={toRight ? 'start' : 'end'}
        className="pointer-events-none font-mono text-[8.5px] tracking-tight"
        fill={isHovered ? 'var(--color-text-primary)' : 'var(--color-text-secondary)'}
      >
        {label}
      </text>
    </g>
  )
}

// Callout badge that appears above (or below, near the top edge) a hovered
// node, making its MAC address legible even when the node's own label shows
// a nickname or hostname instead — and even at high node density where
// labels overlap.
function MacHighlight({ node }) {
  if (!node) return null
  const width = node.mac.length * 5.3 + 16
  const height = 16
  const above = node.y > 70
  const boxY = above ? node.y - 14 - height : node.y + 14
  return (
    <g className="pointer-events-none">
      <rect
        x={node.x - width / 2}
        y={boxY}
        width={width}
        height={height}
        rx={2}
        fill="var(--color-surface-elevated)"
        stroke="var(--color-accent-green)"
        strokeWidth={1}
      />
      <text
        x={node.x}
        y={boxY + height / 2 + 3}
        textAnchor="middle"
        className="font-mono text-[9px] font-semibold tracking-wide"
        fill="var(--color-accent-green)"
      >
        {node.mac}
      </text>
    </g>
  )
}

function sectorLabelAnchor(midAngle) {
  const cos = Math.cos(midAngle)
  if (cos > 0.15) return 'start'
  if (cos < -0.15) return 'end'
  return 'middle'
}

/**
 * Renders the radial network map: distance from center encodes urgency
 * (THREAT/WATCH/CALM rings), angle encodes AP segment. `layout` is the
 * output of computeNodeLayout(). `degraded` tints the core red/amber when
 * useHealth() reports a scheduler/service problem.
 */
export function NetworkMap({ layout, degraded }) {
  const navigate = useNavigate()
  const { nodes, sectors } = layout
  const coreColor = degraded ? 'var(--color-accent-red)' : 'var(--color-accent-green)'
  const [hoveredMac, setHoveredMac] = useState(null)
  const hoveredNode = hoveredMac ? nodes.find((n) => n.mac === hoveredMac) : null

  function handleSelect(mac) {
    navigate(`/devices/${mac}`)
  }

  return (
    <svg viewBox="0 0 1000 760" className="h-full w-full" role="img" aria-label="Network map of connected devices">
      <defs>
        <radialGradient id="nm-core" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={coreColor} stopOpacity="0.9" />
          <stop offset="55%" stopColor={coreColor} stopOpacity="0.3" />
          <stop offset="100%" stopColor={coreColor} stopOpacity="0" />
        </radialGradient>
        <radialGradient id="nm-threatzone" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--color-accent-red)" stopOpacity="0.14" />
          <stop offset="100%" stopColor="var(--color-accent-red)" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* urgency rings */}
      <circle cx={CX} cy={CY} r={TIER_RADIUS.THREAT} fill="url(#nm-threatzone)" />
      <g stroke="var(--color-border)" fill="none">
        <circle cx={CX} cy={CY} r={TIER_RADIUS.THREAT} />
        <circle cx={CX} cy={CY} r={TIER_RADIUS.WATCH} />
        <circle cx={CX} cy={CY} r={TIER_RADIUS.CALM} />
      </g>
      <text x={CX} y={CY - TIER_RADIUS.THREAT - 8} textAnchor="middle" className="font-mono text-[9px] tracking-[3px]" fill="var(--color-text-muted)">
        THREAT
      </text>
      <text x={CX} y={CY - TIER_RADIUS.WATCH - 8} textAnchor="middle" className="font-mono text-[9px] tracking-[3px]" fill="var(--color-text-muted)">
        WATCH
      </text>
      <text x={CX} y={CY - TIER_RADIUS.CALM - 8} textAnchor="middle" className="font-mono text-[9px] tracking-[3px]" fill="var(--color-text-muted)">
        CALM
      </text>

      {/* sector dividers + labels */}
      <g stroke="var(--color-border)">
        {sectors.map((s) => (
          <line
            key={s.label}
            x1={CX}
            y1={CY}
            x2={CX + Math.cos(s.startAngle) * OUTER_RADIUS}
            y2={CY + Math.sin(s.startAngle) * OUTER_RADIUS}
          />
        ))}
      </g>
      {sectors.map((s) => (
        <text
          key={s.label}
          x={CX + Math.cos(s.midAngle) * (TIER_RADIUS.CALM + 22)}
          y={CY + Math.sin(s.midAngle) * (TIER_RADIUS.CALM + 22)}
          textAnchor={sectorLabelAnchor(s.midAngle)}
          className="font-mono text-[10.5px] tracking-[2px]"
          fill="var(--color-accent-blue)"
        >
          {s.label}
        </text>
      ))}

      {/* bridges drawn before nodes so nodes sit on top */}
      <g>
        {nodes.map((n) => (
          <Bridge key={n.mac} node={n} />
        ))}
      </g>
      <g>
        {nodes.map((n) => (
          <Node
            key={n.mac}
            node={n}
            onSelect={handleSelect}
            isHovered={n.mac === hoveredMac}
            onHover={setHoveredMac}
          />
        ))}
      </g>

      {/* core */}
      <circle
        cx={CX}
        cy={CY}
        r={70}
        fill="url(#nm-core)"
        className="network-map-anim origin-center animate-[network-map-breathe_4.5s_ease-in-out_infinite]"
      />
      <circle cx={CX} cy={CY} r={22} fill="var(--color-bg)" stroke={coreColor} strokeWidth={1.5} />
      <text x={CX} y={CY - 4} textAnchor="middle" className="font-mono text-[9px] tracking-[2px]" fill={coreColor}>
        HEIMDALL
      </text>
      <text x={CX} y={CY + 10} textAnchor="middle" className="font-mono text-[7px] tracking-[2px]" fill="var(--color-text-muted)">
        WATCHTOWER
      </text>

      <MacHighlight node={hoveredNode} />
    </svg>
  )
}
