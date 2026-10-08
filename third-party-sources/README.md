# Covered River source access

These archives contain the exact unmodified River modules at `v0.39.0` used by the API and worker. The covered source is available under **MPL-2.0**, with the embedded MIT component retaining its own terms. Original RTM restrictions do not limit these source rights. Each archive preserves upstream source and license files; the manifest records upstream URL, SHA-256 and the matching `backend/go.sum` checksum.

API and worker images include this directory at `/usr/share/licenses/rtm/third-party-sources`, alongside the full license collection. Frontend bundles also carry the source pack at `/legal/third-party-sources/`. No request to the project owner or network download is needed to obtain these covered files from those artifacts.

For a standalone executable, distribute `LICENSE`, `BRANDING.md`, `THIRD_PARTY_NOTICES.md`, `third-party-licenses/` and this directory alongside it. An image can be inspected with `docker create` and `docker cp` without starting the service. Preserve this source-access notice with the distribution. If a future build changes any covered module or source, refresh its corresponding archive and manifest before distributing it; these files cover the recorded version only.
