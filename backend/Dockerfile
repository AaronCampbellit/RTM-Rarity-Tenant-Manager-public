# Multi-stage build producing two single-binary images (api, worker).
FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend ./
COPY LICENSE BRANDING.md THIRD_PARTY_NOTICES.md /out/legal/
COPY third-party-licenses /out/legal/third-party-licenses
COPY third-party-sources /out/legal/third-party-sources
RUN CGO_ENABLED=0 go build -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -o /out/worker ./cmd/worker

FROM gcr.io/distroless/static-debian12 AS api
COPY --from=build /out/api /api
COPY --from=build /out/legal /usr/share/licenses/rtm
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/api"]

FROM gcr.io/distroless/static-debian12 AS worker
COPY --from=build /out/worker /worker
COPY --from=build /out/legal /usr/share/licenses/rtm
USER nonroot:nonroot
ENTRYPOINT ["/worker"]
