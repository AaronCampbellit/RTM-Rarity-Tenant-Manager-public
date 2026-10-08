# Design QA — compact Attack Storylines queue

## Source and target

- Reference: `/home/acampbell/.codex/attachments/81b80848-914d-48f1-b92d-dd33fba38c78/codex-clipboard-3b2d8126-9497-4747-864a-f10c21dcfaab.png`
- Reference dimensions: 1568 × 136 px
- Implemented screen: Security Operations → Attack storylines
- Desktop viewport: 1440 × 1000 px at 1× density
- Mobile viewport: 390 × 844 px at 1× density
- Verified states: default Active/risk sort, text search, In Progress filter, alphabetical sort, storyline detail drawer, and all-status mobile view

## Evidence

- Desktop component: `/tmp/rtm-attack-storylines-desktop.png`
- Filtered component: `/tmp/rtm-attack-storylines-filtered.png`
- Mobile component: `/tmp/rtm-attack-storylines-mobile.png`
- Storyline drawer: `/tmp/rtm-attack-storyline-drawer.png`
- Reference/implementation comparison: `/tmp/rtm-attack-storylines-comparison.png`

## Comparison findings

The reference provides the Incident Queue control pattern rather than a full Attack Storylines layout. The implementation deliberately reuses that pattern at RTM's compact card scale and adds the two storyline-specific controls the workflow requires: status history and sort order.

- Search, tenant, severity, status, and refresh controls match the existing RTM queue vocabulary and visual tokens.
- The compact rows preserve analyst-scannable severity, status, risk, signal count, tenant, primary entity, and recency without restoring the former large storyline tiles.
- Active is the default state; resolved and dismissed storylines remain retrievable.
- The section has a bounded scroll area and does not increase page width at 390 px.
- No new image assets were required; existing Lucide icons and RTM design tokens are used.
- No console errors, console warnings, page errors, or horizontal overflow were found in the tested states.

## QA history

1. Initial automated interaction pass verified behavior but exposed that the QA script had retained Playwright's default viewport.
2. The pass was repeated with explicit 1440 × 1000 and 390 × 844 viewports.
3. The corrected pass verified search, filtering, sorting, refresh availability, row selection, drawer content, responsive controls, and zero horizontal overflow.
4. The corrected desktop capture was compared with the supplied Incident Queue toolbar in one combined visual.

## Automated checks

- `npm test` — 70 tests passed
- `npm run build` — passed
- `git diff --check` — passed before this report was added

## Result

passed
