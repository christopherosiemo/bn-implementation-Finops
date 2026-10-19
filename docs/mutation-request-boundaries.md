# Control-plane request boundaries

Control-plane POST bodies have a 4 MiB (4,194,304 byte) limit, including JSON
whitespace. The API reads at most one additional byte to distinguish a complete
boundary-sized body from a longer body. It rejects the latter with HTTP 413 and
`{"error":"BODY_TOO_LARGE","message":"request body exceeds 4 MiB"}` before
JSON parsing, request hashing, cached-response selection, fixture seeding or any
database access. A valid JSON prefix is never treated as the whole request.

The API authenticates the request and checks the route's current roles and
required idempotency key before reading a mutation body. Exactly 4 MiB remains
supported. A rejected body reserves no idempotency key, appends no audit/outbox
event and cannot borrow a cached response for its prefix. An authorized retry of
the original complete body preserves its original status, response and ETag.
Dedicated machine ingress services retain their separate limits and contracts.

The console proxy has a separate 5 MiB transport ceiling under `/v1/`, allowing
the API to enforce its 4 MiB boundary and authorization ordering for supported
requests and one-byte overflow. Beyond the edge ceiling, Nginx rejects the
transport with the same static JSON 413 without authenticating or forwarding it.
That edge rejection establishes no API authorization decision. Responses from
the API, including its 413, pass through unchanged. The difference between these
two boundaries prevents Nginx's default 1 MiB ceiling from rejecting supported
API bodies. See the [Nginx directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size).

Actual signed JWT/JWKS and restricted PostgreSQL acceptance covers exact-cap
bodies, known and streamed framing, misleading handler content lengths, hidden
suffixes, cache-prefix confusion, bounded reads, unchanged persisted state and
subsequent valid reconciliation. The separate isolated Nginx lab exercises the
proxy with a visibly identified upstream double. Its source-bound acceptance
does not stand in for the connected application and process-recovery suites.
