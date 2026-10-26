---
version: "1.0"
name: Beaver
description: A quiet, evidence-first network security console.
colors:
  background: "#0b1018"
  surface: "#101923"
  primary: "#62dfac"
  text: "#edf3fc"
  muted: "#9bacc2"
  border: "#273648"
  danger: "#ff8998"
typography:
  sans:
    fontFamily: "Segoe UI, system-ui, sans-serif"
  mono:
    fontFamily: "Cascadia Code, Consolas, monospace"
rounded:
  DEFAULT: "8px"
spacing:
  section-gap: "20px"
components:
  button: {}
  panel: {}
  dialog: {}
  table: {}
---
# Beaver Design System

## Overview
### Creative North Star
A calm instrument panel for inspecting the boundaries of your computer. The shield status band is the signature; actual coverage governs its words. Concept: docs/design-concept.png.
### Product context and register
Windows and Linux desktop users investigating network activity. Product register, English initial release, global audience. No threat theatre or fabricated security claims. Single-user local application. Runtime tokens in src/styles.css own the implemented values mirrored here.
## Colors
Ink background, blue-gray panel borders, mint active signals, rose danger, amber uncertainty. Always label states with text. Focus is mint.
## Typography
Segoe UI/system sans for product, Cascadia Code/Consolas for IPs. Tabular numbers. Heading 30px; body 14px; labels 12px.
## Layout
220px navigation rail; flexible main area with 28px inset. Three metrics then 2:1 chart and coverage, then applications and alerts. At 1050px collapse rail to icons; at 760px stack panels. Tables own horizontal overflow; main document owns vertical scroll.
## Elevation & Depth
Thin borders and tonal surfaces. Only modals cast a shadow. No decorative gradients; chart fill conveys volume.
## Shapes
8px panels and buttons. Lucide outline icons at 18px with 1.7px strokes.
## Components
### Foundational visual states
Shared Button, Panel, RiskBadge, Empty, Search, Confirm and TrafficChart components. Clear pending, disconnected, partial, empty, error, success and disabled states.
### Buttons and actions
Mint primary, bordered neutral, rose dangerous. 36px minimum control height, stable busy labels.
### Navigation and data display
Semantic tables, bounded 20-row application pages, local search. Risk labels are textual. Unavailable metrics are em dashes.
### Forms and overlays
Native select is deliberate for desktop OS familiarity. Native HTML dialog shown modally owns confirmation, focus and Escape. No browser confirm. Settings save immediately and report errors; no unsaved draft.
### Iconography
Lucide, consistently outlined. Labels stay visible in compact navigation as accessible names.
### Motion
120ms hover only; reduced-motion disables transitions.
### Content and data visualization
Do not equate Low Risk with safe. Explain evidence and coverage. Speeds are bytes/s. System and attributed packet measurements are labelled separately.
## Do
Use truthful coverage and consistent actions. Keep technical details in investigations.
## Don't
Invent traffic, threat counts, geography, or verified protection.
