---
name: Obsidian Sentinel
colors:
  surface: '#111318'
  surface-dim: '#111318'
  surface-bright: '#37393e'
  surface-container-lowest: '#0c0e12'
  surface-container-low: '#1a1c20'
  surface-container: '#1e2024'
  surface-container-high: '#282a2e'
  surface-container-highest: '#333539'
  on-surface: '#e2e2e8'
  on-surface-variant: '#c2c6d6'
  inverse-surface: '#e2e2e8'
  inverse-on-surface: '#2f3035'
  outline: '#8c909f'
  outline-variant: '#424754'
  surface-tint: '#adc6ff'
  primary: '#adc6ff'
  on-primary: '#002e6a'
  primary-container: '#4d8eff'
  on-primary-container: '#00285d'
  inverse-primary: '#005ac2'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffb786'
  on-tertiary: '#502400'
  tertiary-container: '#df7412'
  on-tertiary-container: '#461f00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a42'
  on-primary-fixed-variant: '#004395'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffdcc6'
  tertiary-fixed-dim: '#ffb786'
  on-tertiary-fixed: '#311400'
  on-tertiary-fixed-variant: '#723600'
  background: '#111318'
  on-background: '#e2e2e8'
  surface-variant: '#333539'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 30px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  label-mono:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.02em
  data-tabular:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 16px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  element-gap: 12px
  table-row-height: 40px
  sidebar-width: 240px
  sidebar-collapsed: 64px
---

## Brand & Style
The design system is engineered for high-stakes Security Operations Centers (SOC). It prioritizes **Cognitive Clarity** over visual flair, moving away from "hacker" tropes toward a refined, institutional aesthetic. The brand personality is authoritative, vigilant, and precise.

The visual direction follows a **Modern Enterprise** approach with a **Dark-first** foundation. It utilizes high-information density, subtle depth through tonal layering rather than aggressive shadows, and a strict semantic color application. Every UI element is designed to facilitate the "Detect → Understand → Investigate → Decide → Remediate" workflow, ensuring that critical data is never obscured by decorative elements.

## Colors
The palette is rooted in a deep slate/charcoal base to minimize eye strain during long shifts. 
- **Primary Cyber Blue (#3b82f6)** is reserved strictly for active investigation paths and primary CTA buttons.
- **Emerald (#10b981)** signifies system health and successful remediation.
- **Severity Hierarchy:** Colors are mapped to alert intensity. Critical issues use a ruby red to create immediate visual salience.
- **Backgrounds:** A three-tier background system (Base, Surface, Elevated) creates logical grouping without the need for heavy borders.

## Typography
This design system utilizes **Inter** for its exceptional legibility in dense interfaces. **JetBrains Mono** is introduced as a secondary functional font for technical metadata, IP addresses, and log snippets to ensure distinct character recognition (e.g., distinguishing '0' from 'O').

Typography is intentionally compact to maximize the amount of visible data on screen. Use `label-mono` for all telemetry data and `data-tabular` for cell content within investigation tables.

## Layout & Spacing
The layout follows a **Fixed Shell / Fluid Content** model. 
- **App Shell:** A persistent left sidebar for global navigation. 
- **Three-Pane Layout:** Designed for deep investigations—Left (Alert List), Center (Detail/Graph), Right (Metadata/Timeline).
- **Density:** Spacing is tight (4px base unit) to ensure analysts can see multiple alert rows without scrolling.
- **Investigation Drawers:** Side-sliding panels used for quick-look entity details (Users, IPs, Hostnames) without breaking the primary context.

## Elevation & Depth
Elevation is achieved through **Tonal Layers** and subtle 1px borders rather than traditional shadows. 
- **Level 0 (Base):** #0a0c10 (The primary canvas).
- **Level 1 (Surface):** #111827 (Card backgrounds, Sidebars).
- **Level 2 (Elevated):** #1f2937 (Active Investigation Drawers, Modals).

Shadows are restrained to a single "Low-Profile" style: `0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)`. This maintains the professional, serious tone of a data-heavy application.

## Shapes
The design system uses a **Soft (0.25rem)** roundedness level. This provides a modern feel without the playfulness of fully rounded corners. 
- **Small Elements:** Buttons and Checkboxes use 4px (0.25rem).
- **Large Elements:** Alert Cards and Investigation Drawers use 8px (0.5rem).
- **Indicators:** ML Health and Connectivity status dots remain perfect circles.

## Components

### SeverityBadge
Used to categorize alerts. Format: `[Dot Indicator] + [Severity Text]`. The background should be a 10% opacity tint of the severity color with a 100% opacity text color.

### RiskScore (0-100)
A circular gauge or a bold numeric display. Scores > 80 use the Critical Red color; scores < 30 use the Slate color. 

### Data Tables (Live Telemetry)
- **Row Height:** Strictly 40px for maximum density.
- **Hover State:** Subtle background shift to #1f2937.
- **Active State:** 2px Cyber Blue left-border accent.

### Interactive Graph
Nodes represent entities (User, Process, IP). Edges (lines) represent events. 
- **Node Highlight:** Primary Blue outer glow when selected.
- **Risk Propagation:** Edges connected to "Critical" nodes are tinted Red.

### Investigation Drawers
Slides from the right, taking up 40% of the screen width. Uses a semi-transparent backdrop blur (12px) to maintain a sense of the underlying context.

### MLStatusIndicator
A pulsing dot combined with a label (e.g., "ML Tuning", "Model Active"). Pulse animation should be slow and non-distracting.