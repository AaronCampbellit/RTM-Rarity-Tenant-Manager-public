# RTM Console — Frontend

React + Vite + TypeScript + Tailwind. Implements every screen in the v1 design
handoff against RTM's finalized frontend stack.

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # type-check + production build
```

## Mock vs. real API

All data flows through [`src/api/client.ts`](src/api/client.ts), which mirrors
the REST contract in `../RTM API Specification.md`. By default it serves an
in-memory mock (`src/api/mock.ts`) so the UI runs with no backend.

- `VITE_USE_MOCK=true` (default) — in-memory data, small simulated latency.
- `VITE_USE_MOCK=false` — real calls to `/api/v1` (Vite proxies to `:8080`).

Method signatures and return shapes are identical in both modes, so wiring the
real backend needs **no component changes**.

## Structure (feature-based — Coding Standards)

```
src/
├── api/         client (real + mock), typed hooks, mock dataset
├── components/
│   ├── ui/      shadcn-style primitives (button, card, badge, table, dialog…)
│   ├── common/  DataTable, Avatar, status tones, toolbars
│   ├── layout/  AppShell, Sidebar, Header, TenantSwitcher, nav
│   └── modals/  What-If gate, Save-as-Working-Set
├── features/    one folder per screen (dashboard, tenants, users, …)
├── store/       tenant context, modals, page title
├── types/       API model types (the /api/v1 contract)
└── index.css    design tokens (@theme) — the source of truth for the theme
```

## Design tokens

The dark-grey surface palette, single red accent, typography, radii, and density
from the handoff live in [`src/index.css`](src/index.css). Accent and density
are runtime CSS variables (`--ac`, `--acb`, `--act`, `--rp`) so the theme stays
swappable, exactly as the prototype intended.

## Components & shadcn/ui

The UI primitives in `components/ui` are hand-written in the shadcn/ui style
(same file layout, `cva` variants, `cn()` merge) and themed to the RTM tokens.
This keeps the BETA dependency-light and deterministic; they can be replaced
one-for-one with upstream shadcn/ui + Radix later without touching feature code.
