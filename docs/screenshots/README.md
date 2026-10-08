# RTM screenshots

These are unedited browser screenshots of RTM's implemented frontend, captured
locally with Chromium at **1600 × 1080**. They use the repository's built-in
synthetic dataset in [`frontend/src/api/mock.ts`](../../frontend/src/api/mock.ts)
and its sample administrator. No customer tenant, Microsoft account, API key,
production deployment, or real security incident was accessed for these captures.

| File | Screen and state |
|---|---|
| `security-operations.png` | `/security`, with sample-source coverage and the attack-storyline queue. |
| `tenant-users.png` | `/users`, with the synthetic Contoso directory and hybrid identity labels. |
| `what-if-preview.png` | `/users`, previewing Block sign-in for Avery Quinn and Caleb Stone. Avery is eligible; Caleb is blocked because the object is mastered by on-prem AD. No change was executed. |
| `attack-storyline.png` | `/security`, with the sample account-takeover storyline drawer open. |

## Reproduce

From the repository root, with Node.js 24+ installed:

```bash
cd frontend
npm ci
VITE_USE_MOCK=true npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`, set the browser viewport to 1600 × 1080, and
follow the [README walkthrough](../../README.md#try-it-locally). Wait for the
mock data to load before capturing each screen. The What-If screenshot uses
**Run What If → Block sign-in → Generate Preview** and stops before execution.

Names and organizations, directory records, totals, timestamps, incident evidence,
and risk scores are illustrative fixtures. Screenshot content demonstrates the
rendered application, not successful live provider connections or real tenant posture.
