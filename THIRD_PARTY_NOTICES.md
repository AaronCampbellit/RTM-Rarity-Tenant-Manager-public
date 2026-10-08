# Third-party notices — Rarity Tenant Manager

Original Aaron Campbell material retains the terms in [LICENSE](LICENSE). Third-party components retain their own licenses and copyright notices. Those terms, including permission to use or modify covered components, are not replaced by the original-material restrictions. Rarity names and branding remain subject to [BRANDING.md](BRANDING.md).

This collection records the dependencies and available license texts inspected on **2026-10-08**, against dependency baseline `6c1ed45811c53baf30a322f8cc6fa94943f79ec3`. It distinguishes source references from software included in a distributed bundle or binary. The [machine-readable inventory](third-party-licenses/manifest.json) records exact versions, upstream sources and hashes of verbatim copied texts. It is a bounded component inventory, not full release or container license clearance.

## Frontend runtime components

The following locked and installed runtime packages are conservatively included for frontend distribution. Preserve the applicable full texts with delivered bundles; short generated headers do not replace the license grants. Lucide includes ISC material and Feather-derived MIT icon portions.

| Component | Version | Terms | Copied texts | Source |
| --- | --- | --- | --- | --- |
| `class-variance-authority` | `0.7.1` | Apache-2.0 | [LICENSE](third-party-licenses/npm/class-variance-authority-0.7.1/LICENSE) | [source](https://github.com/joe-bell/cva) |
| `clsx` | `2.1.1` | MIT | [license](third-party-licenses/npm/clsx-2.1.1/license) | [source](https://github.com/lukeed/clsx) |
| `cookie` | `1.1.1` | MIT | [LICENSE](third-party-licenses/npm/cookie-1.1.1/LICENSE) | [source](https://github.com/jshttp/cookie) |
| `js-tokens` | `4.0.0` | MIT | [LICENSE](third-party-licenses/npm/js-tokens-4.0.0/LICENSE) | [source](https://github.com/lydell/js-tokens) |
| `loose-envify` | `1.4.0` | MIT | [LICENSE](third-party-licenses/npm/loose-envify-1.4.0/LICENSE) | [source](https://github.com/zertosh/loose-envify) |
| `lucide-react` | `0.460.0` | ISC; MIT for Feather-derived portions | [LICENSE](third-party-licenses/npm/lucide-react-0.460.0/LICENSE)<br>[FEATHER-LICENSE](third-party-licenses/npm/lucide-react-0.460.0/FEATHER-LICENSE) | [source](https://github.com/lucide-icons/lucide) |
| `react` | `18.3.1` | MIT | [LICENSE](third-party-licenses/npm/react-18.3.1/LICENSE) | [source](https://github.com/facebook/react) |
| `react-dom` | `18.3.1` | MIT | [LICENSE](third-party-licenses/npm/react-dom-18.3.1/LICENSE) | [source](https://github.com/facebook/react) |
| `react-router` | `7.18.2` | MIT | [LICENSE.md](third-party-licenses/npm/react-router-7.18.2/LICENSE.md) | [source](https://github.com/remix-run/react-router) |
| `react-router-dom` | `7.18.2` | MIT | [LICENSE.md](third-party-licenses/npm/react-router-dom-7.18.2/LICENSE.md) | [source](https://github.com/remix-run/react-router) |
| `scheduler` | `0.23.2` | MIT | [LICENSE](third-party-licenses/npm/scheduler-0.23.2/LICENSE) | [source](https://github.com/facebook/react) |
| `set-cookie-parser` | `2.7.2` | MIT | [LICENSE](third-party-licenses/npm/set-cookie-parser-2.7.2/LICENSE) | [source](https://github.com/nfriedly/set-cookie-parser) |
| `tailwind-merge` | `2.6.1` | MIT | [LICENSE.md](third-party-licenses/npm/tailwind-merge-2.6.1/LICENSE.md) | [source](https://github.com/dcastil/tailwind-merge) |

Tailwind CSS is installed as a build dependency, but its generated preflight/theme CSS appears in the delivered stylesheet. Its MIT text is included in the tools table below and must accompany that generated material. The additional Feather text is copied from a tagged primary upstream license to supplement the MIT attribution in the installed older Lucide license; this does not assert a separate Feather package version in RTM.

## Go executable dependencies

These modules were observed by `go list -deps` for the production executable entry points. Full files are retained, including applicable NOTICE files and nested component licenses. A module containing several licenses is listed with those texts rather than reduced to one grant.

| Component | Version | Terms | Copied texts | Source |
| --- | --- | --- | --- | --- |
| `github.com/davecgh/go-spew` | `v1.1.1` | ISC | [LICENSE](third-party-licenses/go/github.com/davecgh/go-spew/v1.1.1/LICENSE) | [source](https://proxy.golang.org/github.com/davecgh/go-spew/@v/v1.1.1.zip) |
| `github.com/go-chi/chi/v5` | `v5.3.0` | MIT | [LICENSE](third-party-licenses/go/github.com/go-chi/chi/v5/v5.3.0/LICENSE) | [source](https://proxy.golang.org/github.com/go-chi/chi/v5/@v/v5.3.0.zip) |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | MIT | [LICENSE](third-party-licenses/go/github.com/golang-jwt/jwt/v5/v5.3.1/LICENSE) | [source](https://proxy.golang.org/github.com/golang-jwt/jwt/v5/@v/v5.3.1.zip) |
| `github.com/jackc/pgpassfile` | `v1.0.0` | MIT | [LICENSE](third-party-licenses/go/github.com/jackc/pgpassfile/v1.0.0/LICENSE) | [source](https://proxy.golang.org/github.com/jackc/pgpassfile/@v/v1.0.0.zip) |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | MIT | [LICENSE](third-party-licenses/go/github.com/jackc/pgservicefile/v0.0.0-20240606120523-5a60cdf6a761/LICENSE) | [source](https://proxy.golang.org/github.com/jackc/pgservicefile/@v/v0.0.0-20240606120523-5a60cdf6a761.zip) |
| `github.com/jackc/pgx/v5` | `v5.10.0` | MIT | [LICENSE](third-party-licenses/go/github.com/jackc/pgx/v5/v5.10.0/LICENSE) | [source](https://proxy.golang.org/github.com/jackc/pgx/v5/@v/v5.10.0.zip) |
| `github.com/jackc/puddle/v2` | `v2.2.2` | MIT | [LICENSE](third-party-licenses/go/github.com/jackc/puddle/v2/v2.2.2/LICENSE) | [source](https://proxy.golang.org/github.com/jackc/puddle/v2/@v/v2.2.2.zip) |
| `github.com/mfridman/interpolate` | `v0.0.2` | MIT | [LICENSE.txt](third-party-licenses/go/github.com/mfridman/interpolate/v0.0.2/LICENSE.txt) | [source](https://proxy.golang.org/github.com/mfridman/interpolate/@v/v0.0.2.zip) |
| `github.com/pmezard/go-difflib` | `v1.0.0` | BSD-family (preserve full text) | [LICENSE](third-party-licenses/go/github.com/pmezard/go-difflib/v1.0.0/LICENSE) | [source](https://proxy.golang.org/github.com/pmezard/go-difflib/@v/v1.0.0.zip) |
| `github.com/pressly/goose/v3` | `v3.27.2` | MIT | [LICENSE](third-party-licenses/go/github.com/pressly/goose/v3/v3.27.2/LICENSE) | [source](https://proxy.golang.org/github.com/pressly/goose/v3/@v/v3.27.2.zip) |
| `github.com/riverqueue/river` | `v0.39.0` | MPL-2.0 | [LICENSE](third-party-licenses/go/github.com/riverqueue/river/v0.39.0/LICENSE) | [source](https://proxy.golang.org/github.com/riverqueue/river/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/riverdriver` | `v0.39.0` | MPL-2.0 | [LICENSE](third-party-licenses/go/github.com/riverqueue/river/riverdriver/v0.39.0/LICENSE) | [source](https://proxy.golang.org/github.com/riverqueue/river/riverdriver/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/riverdriver/riverpgxv5` | `v0.39.0` | MPL-2.0 | [LICENSE](third-party-licenses/go/github.com/riverqueue/river/riverdriver/riverpgxv5/v0.39.0/LICENSE) | [source](https://proxy.golang.org/github.com/riverqueue/river/riverdriver/riverpgxv5/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/rivershared` | `v0.39.0` | MIT; MPL-2.0 | [LICENSE](third-party-licenses/go/github.com/riverqueue/river/rivershared/v0.39.0/LICENSE)<br>[License.txt](third-party-licenses/go/github.com/riverqueue/river/rivershared/v0.39.0/levenshtein/License.txt) | [source](https://proxy.golang.org/github.com/riverqueue/river/rivershared/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/rivertype` | `v0.39.0` | MPL-2.0 | [LICENSE](third-party-licenses/go/github.com/riverqueue/river/rivertype/v0.39.0/LICENSE) | [source](https://proxy.golang.org/github.com/riverqueue/river/rivertype/@v/v0.39.0.zip) |
| `github.com/sethvargo/go-retry` | `v0.3.0` | Apache-2.0 | [LICENSE](third-party-licenses/go/github.com/sethvargo/go-retry/v0.3.0/LICENSE) | [source](https://proxy.golang.org/github.com/sethvargo/go-retry/@v/v0.3.0.zip) |
| `github.com/stretchr/testify` | `v1.11.1` | MIT | [LICENSE](third-party-licenses/go/github.com/stretchr/testify/v1.11.1/LICENSE) | [source](https://proxy.golang.org/github.com/stretchr/testify/@v/v1.11.1.zip) |
| `github.com/tidwall/gjson` | `v1.19.0` | MIT | [LICENSE](third-party-licenses/go/github.com/tidwall/gjson/v1.19.0/LICENSE) | [source](https://proxy.golang.org/github.com/tidwall/gjson/@v/v1.19.0.zip) |
| `github.com/tidwall/match` | `v1.2.0` | MIT | [LICENSE](third-party-licenses/go/github.com/tidwall/match/v1.2.0/LICENSE) | [source](https://proxy.golang.org/github.com/tidwall/match/@v/v1.2.0.zip) |
| `github.com/tidwall/pretty` | `v1.2.1` | MIT | [LICENSE](third-party-licenses/go/github.com/tidwall/pretty/v1.2.1/LICENSE) | [source](https://proxy.golang.org/github.com/tidwall/pretty/@v/v1.2.1.zip) |
| `github.com/tidwall/sjson` | `v1.2.5` | MIT | [LICENSE](third-party-licenses/go/github.com/tidwall/sjson/v1.2.5/LICENSE) | [source](https://proxy.golang.org/github.com/tidwall/sjson/@v/v1.2.5.zip) |
| `go.uber.org/goleak` | `v1.3.0` | MIT | [LICENSE](third-party-licenses/go/go.uber.org/goleak/v1.3.0/LICENSE) | [source](https://proxy.golang.org/go.uber.org/goleak/@v/v1.3.0.zip) |
| `go.uber.org/multierr` | `v1.11.0` | MIT | [LICENSE.txt](third-party-licenses/go/go.uber.org/multierr/v1.11.0/LICENSE.txt) | [source](https://proxy.golang.org/go.uber.org/multierr/@v/v1.11.0.zip) |
| `golang.org/x/crypto` | `v0.56.0` | BSD-family (preserve full text) | [LICENSE](third-party-licenses/go/golang.org/x/crypto/v0.56.0/LICENSE) | [source](https://proxy.golang.org/golang.org/x/crypto/@v/v0.56.0.zip) |
| `golang.org/x/sync` | `v0.22.0` | BSD-family (preserve full text) | [LICENSE](third-party-licenses/go/golang.org/x/sync/v0.22.0/LICENSE) | [source](https://proxy.golang.org/golang.org/x/sync/@v/v0.22.0.zip) |
| `golang.org/x/text` | `v0.41.0` | BSD-family (preserve full text) | [LICENSE](third-party-licenses/go/golang.org/x/text/v0.41.0/LICENSE) | [source](https://proxy.golang.org/golang.org/x/text/@v/v0.41.0.zip) |
| `gopkg.in/yaml.v3` | `v3.0.1` | Apache-2.0; MIT | [LICENSE](third-party-licenses/go/gopkg.in/yaml.v3/v3.0.1/LICENSE)<br>[NOTICE](third-party-licenses/go/gopkg.in/yaml.v3/v3.0.1/NOTICE) | [source](https://proxy.golang.org/gopkg.in/yaml.v3/@v/v3.0.1.zip) |

| Component | Version | Terms | Copied texts | Source |
| --- | --- | --- | --- | --- |
| `Go runtime and standard library` | `go1.26.8` | BSD-3-Clause | [LICENSE](third-party-licenses/go-runtime/go1.26.8/LICENSE) | [source](https://go.googlesource.com/go/+/refs/tags/go1.26.8/LICENSE) |

## River MPL source access

River and its four imported submodules at `v0.39.0` have MPL-2.0 main licenses. The `rivershared/levenshtein` component has its own MIT license, also included above. MPL applies to the covered files, while the separate original larger work may retain its own terms.

If distributing executables containing covered River software, make the corresponding MPL-covered source, including any covered-file modifications, available under MPL-2.0 and tell recipients how to obtain it. Preserve notices and do not use the original-material restrictions to limit recipients’ covered-source rights. See [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) and the [official MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

The exact unmodified archives are delivered in [third-party-sources/](third-party-sources/README.md), with hashes and Go checksums in its [manifest](third-party-sources/manifest.json). API and worker images include them at `/usr/share/licenses/rtm/third-party-sources`; built frontend output includes them at `/legal/third-party-sources/`. Covered source retains MPL-2.0 and nested component terms. This mechanism covers the recorded dependencies; future covered-source changes require matching archive updates.

| Covered module | Exact upstream source archive |
| --- | --- |
| `github.com/riverqueue/river@v0.39.0` | [source archive](https://proxy.golang.org/github.com/riverqueue/river/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/riverdriver@v0.39.0` | [source archive](https://proxy.golang.org/github.com/riverqueue/river/riverdriver/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/riverdriver/riverpgxv5@v0.39.0` | [source archive](https://proxy.golang.org/github.com/riverqueue/river/riverdriver/riverpgxv5/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/rivershared@v0.39.0` | [source archive](https://proxy.golang.org/github.com/riverqueue/river/rivershared/@v/v0.39.0.zip) |
| `github.com/riverqueue/river/rivertype@v0.39.0` | [source archive](https://proxy.golang.org/github.com/riverqueue/river/rivertype/@v/v0.39.0.zip) |

## Development and build components

These are selected build/test tools and data with MPL or attribution terms, plus Tailwind generated-CSS terms where applicable. They are not all shipped application libraries. This table is not a complete license pack for redistributing an entire development environment. MPL tool code retains its covered-source requirements if the tool itself or modified covered files are distributed; merely using the tool does not apply MPL to the original application output.

| Component | Version | Terms | Copied texts | Source |
| --- | --- | --- | --- | --- |
| `caniuse-lite` | `1.0.30001814` | CC-BY-4.0 | [LICENSE](third-party-licenses/npm/caniuse-lite-1.0.30001814/LICENSE) | [source](https://github.com/browserslist/caniuse-lite) |
| `lightningcss` | `1.32.0` | MPL-2.0 | [LICENSE](third-party-licenses/npm/lightningcss-1.32.0/LICENSE) | [source](https://github.com/parcel-bundler/lightningcss) |
| `lightningcss-linux-x64-gnu` | `1.32.0` | MPL-2.0 | [LICENSE](third-party-licenses/npm/lightningcss-linux-x64-gnu-1.32.0/LICENSE) | [source](https://github.com/parcel-bundler/lightningcss) |
| `tailwindcss` | `4.3.2` | MIT | [LICENSE](third-party-licenses/npm/tailwindcss-4.3.2/LICENSE) | [source](https://github.com/tailwindlabs/tailwindcss) |

## Separate infrastructure images

The demo configurations reference `postgres:16-alpine`. Runtime images also use `nginx:1.27-alpine` and `gcr.io/distroless/static-debian12`; build stages use Node and Go images. These external references are distinct from checking image contents into this source repository. The floating image tags and their full OS-component license inventories were not audited. Any distributor of built images must inventory their exact contents and preserve all applicable terms, including separate copyleft components where present.

## Automatic notice packaging

`npm run build` includes this notice, the original-material terms and the complete collected license texts at `frontend/dist/legal/`. Runtime Docker stages retain the same collection.

## Checks for each release

- Standalone binaries must be accompanied by the equivalent legal directory.
- Verify that this inventory matches the exact release dependency versions and copied/generated components; update it when dependencies change.
- Complete image-specific license/SBOM and source-delivery checks for the actual images being conveyed. This collection is not a complete container license pack.
- Preserve existing source copyright comments, applicable component notices and brand/asset rights. Older assets without explicit capture provenance are not independently cleared by this dependency inventory.

The copied texts control their respective components. Security scanner results, license-count filters, and this notice do not establish complete license compliance or ownership.
