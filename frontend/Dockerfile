# SentinelFlow frontend image (multi-stage).
#
#   build stage : node -> npm ci -> vite build -> /app/dist
#   serve stage : nginx serves the SPA and reverse-proxies /api + /health +
#                 /ready to the backend service (same origin => no CORS, and
#                 VITE_API_BASE_URL stays empty).

# --- build stage -----------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies first (layer caching); npm ci honors the committed
# package-lock.json for a reproducible install.
COPY package.json package-lock.json ./
RUN npm ci

# Application source (node_modules / dist are excluded via .dockerignore).
COPY . .

# VITE_API_BASE_URL is intentionally empty: the nginx stage proxies /api on the
# SAME origin, so the browser never needs a cross-origin base URL. Override with
# `--build-arg VITE_API_BASE_URL=http://backend-host:8000` ONLY for a split-origin
# deployment where the frontend is served apart from the backend.
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

# --- serve stage -----------------------------------------------------------
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80

# nginx:alpine ships busybox wget — a dependency-free static check that the
# SPA is being served.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO /dev/null http://127.0.0.1/ || exit 1
