ARG NODE_IMAGE=node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:stable-alpine@sha256:782bb89768cc87b7f95c18b95baa1af250e5d451f26794f59363540161147c01
FROM ${NODE_IMAGE} AS build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
COPY contracts/ /app/contracts/
ARG VITE_OIDC_ISSUER=http://localhost:8081/realms/finops
ARG VITE_OIDC_CLIENT_ID=console
ENV VITE_OIDC_ISSUER=$VITE_OIDC_ISSUER VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID
RUN npm run generate && npm run build

FROM ${NGINX_IMAGE}
ENV API_UPSTREAM=api:8080 NGINX_ENVSUBST_OUTPUT_DIR=/tmp NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
COPY frontend/nginx-root.conf /etc/nginx/nginx.conf
COPY frontend/nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/frontend/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O - http://127.0.0.1:8080/healthz || exit 1
