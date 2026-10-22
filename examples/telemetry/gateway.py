"""A real local instrumented HTTP gateway; its target is explicitly a fixture.

This emits requests actually served here. It does not invent host capacity,
historical observations, or application availability from Prometheus scrape up.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import threading
import time

START = time.time()
LOCK = threading.Lock()
REQUESTS = ERRORS = 0
BOUNDS = (0.01, 0.05, 0.1, 0.18, 0.25, 0.5, 1.0)
COUNTS = [0] * (len(BOUNDS) + 1)
TOTAL = 0.0
LABEL = 'finops_resource_id="resource-dev-api"'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        global REQUESTS, ERRORS, TOTAL
        parsed = urlparse(self.path)
        if parsed.path == "/metrics":
            with LOCK:
                lines = [
                    "# TYPE finops_gateway_requests counter",
                    "# UNIT finops_gateway_requests requests",
                    f"finops_gateway_requests_total{{{LABEL}}} {REQUESTS}",
                    f"finops_gateway_requests_created{{{LABEL}}} {START}",
                    "# TYPE finops_gateway_errors counter",
                    "# UNIT finops_gateway_errors errors",
                    f"finops_gateway_errors_total{{{LABEL}}} {ERRORS}",
                    f"finops_gateway_errors_created{{{LABEL}}} {START}",
                    "# TYPE process_start_time_seconds gauge",
                    "# UNIT process_start_time_seconds seconds",
                    f"process_start_time_seconds{{{LABEL}}} {START}",
                    "# TYPE finops_gateway_request_duration_seconds histogram",
                    "# UNIT finops_gateway_request_duration_seconds seconds",
                ]
                cumulative = 0
                for index, bound in enumerate((*BOUNDS, "+Inf")):
                    cumulative += COUNTS[index]
                    lines.append(f'finops_gateway_request_duration_seconds_bucket{{{LABEL},le="{bound}"}} {cumulative}')
                lines += [f"finops_gateway_request_duration_seconds_count{{{LABEL}}} {REQUESTS}", f"finops_gateway_request_duration_seconds_sum{{{LABEL}}} {TOTAL}", f"finops_gateway_request_duration_seconds_created{{{LABEL}}} {START}", "# EOF"]
            raw = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
        elif parsed.path == "/work":
            begin = time.perf_counter()
            query = parse_qs(parsed.query)
            time.sleep(0.02)
            failed = query.get("fail") == ["true"]
            elapsed = time.perf_counter() - begin
            with LOCK:
                REQUESTS += 1
                ERRORS += int(failed)
                TOTAL += elapsed
                index = next((i for i, bound in enumerate(BOUNDS) if elapsed <= bound), len(BOUNDS))
                COUNTS[index] += 1
            raw = b'{"fixture":true,"work_preserved":true}'
            self.send_response(503 if failed else 200)
            self.send_header("Content-Type", "application/json")
        elif parsed.path == "/healthz":
            raw = b'{"fixture":true,"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            self.send_error(404)
            return
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8096), Handler).serve_forever()
