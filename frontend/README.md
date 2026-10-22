# Cloud Cost Autopilot console

React, TypeScript, and Vite console for the AWS operating pilot. Every dashboard value and operation comes from the authenticated API. Fixture data is labelled throughout the UI. Fonts ship locally with the application.

## Development

From this directory:

```sh
npm ci
npm run generate
npm run dev
```

Vite proxies `/v1` to the API at `localhost:8080`. The default public OIDC issuer is `http://localhost:8081/realms/finops`, client `console`; override with `VITE_OIDC_ISSUER` and `VITE_OIDC_CLIENT_ID` at build time. Add the console origin to the identity provider's redirect URI and web-origin allowlists. No client secret is used.

Sign-in uses authorization code with S256 PKCE and state validation. Access, refresh, and ID tokens remain in memory. Only the temporary verifier and state are stored in `sessionStorage`, then removed after the callback. Reloading requires sign-in; an existing provider session can complete it without another password prompt.

## Validation

```sh
npm run typecheck
npm run build
npx playwright install chromium
npm run test:e2e
```

The end-to-end test expects the complete Compose fixture stack at `http://localhost:3000` and the local Keycloak fixture owner. It signs in through Keycloak, connects an account, updates workload evidence, generates a recommendation, acknowledges and creates a signed plan, approves and executes it, observes restoration, verifies savings, exports audit records, and checks mobile navigation. It resets the fixture at the start; run it serially with other mutating acceptance suites. Override `FINOPS_WEB_URL`, `FINOPS_E2E_USER`, and `FINOPS_E2E_PASSWORD` for a dedicated fixture environment. Never point this fixture acceptance suite at a live account.

OpenAPI-generated wire contracts live in `src/api.generated.ts`. Console types refine the document-shaped API records for display. Monetary aggregation uses fixed-scale integer arithmetic; formatting is display-only. Summaries exclude superseded ledger records and keep source currencies separate.

Version-2 execution readiness is independent of savings verification. Only an explicit `pre_execution_ready: true` allows creation of a new plan; a validated baseline can authorize an approved cycle while savings remain `MEASURING`. New approvals and executions require the signed version-2 baseline, measurement and readiness references. Legacy unbound records remain visible as history and are excluded from verified totals. Unknown costs and estimates display as unavailable. Fixture savings identify their synthetic logical financial clock.

`npx playwright test readiness.spec.ts` runs isolated presentation-contract cases for those rules without mutating the fixture API. The complete operating-loop test additionally waits for the bound measurement to pass the ordinary verification gates.

## Container

Build from the repository root using `frontend/Dockerfile`. Build arguments `NODE_IMAGE` and `NGINX_IMAGE` permit a configured registry mirror. The final unprivileged nginx process listens on 8080. `API_UPSTREAM` defaults to `api:8080`; environment substitution writes the upstream configuration to `/tmp/default.conf`. Nameservers come from the platform's `/etc/resolv.conf`, and upstream DNS refreshes every five seconds so API container replacement does not leave stale routing. Kubernetes must provide the API service's full DNS name, including namespace and cluster domain. A read-only root filesystem needs only a writable `/tmp` volume. `/healthz` is a local web liveness check; `/v1` is proxied to the authenticated API. Access logs omit query strings, including OIDC authorization codes.
