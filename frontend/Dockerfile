# Build the SPA and serve it with nginx. The API is reached via the reverse
# proxy (/api → api:8080) configured in nginx.conf.
FROM node:22-alpine AS build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
COPY LICENSE BRANDING.md THIRD_PARTY_NOTICES.md /src/
COPY third-party-licenses /src/third-party-licenses
COPY third-party-sources /src/third-party-sources
ARG VITE_USE_MOCK=false
ENV VITE_USE_MOCK=$VITE_USE_MOCK
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /src/frontend/dist /usr/share/nginx/html
# Git checkouts on hardened build hosts can inherit a restrictive umask.
# Nginx needs read/traverse access to every generated static asset, while the
# worker should not gain write access to the root-owned build output.
RUN chmod -R a+rX /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
