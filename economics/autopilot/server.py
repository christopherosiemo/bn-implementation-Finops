"""Private HTTP worker. No cloud mutation credentials or public ingress."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import csv
import io
import json
import os
from decimal import Decimal
from .model import EvidenceError, evaluate
from .normalize import normalize
from .v2 import evaluate_v2
from .v3 import evaluate_v3
from .native import normalize_v3
from .capacity import evaluate_capacity
from .database import evaluate_database, unique_object as database_unique_object

MAX_BODY = 64 * 1024 * 1024


def runtime_token():
    """An omitted secret must never turn a hosted worker into an open service."""
    fixture = os.getenv("FIXTURE_MODE", "").lower() in ("true", "1", "t") or os.getenv("DATA_MODE") == "fixture"
    token = os.getenv("ECONOMICS_TOKEN", "")
    if len(token) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token) or not token and not fixture:
        raise RuntimeError("ECONOMICS_AUTHENTICATION_CONFIGURATION_INVALID")
    return token


class Handler(BaseHTTPRequestHandler):
    server_version = "AutopilotEconomics/1"

    def log_message(self, *_):
        # Do not log billing payloads, auth headers or resource identities.
        pass

    def reply(self, code, data):
        raw = json.dumps(data, separators=(",", ":"), default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self.reply(200, {"status": "ok", "service": "economics", "focus_version": "1.4"})
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path not in ("/v7/database-assessment", "/v4/capacity", "/v3/evaluate", "/v3/normalize", "/v2/evaluate", "/evaluate", "/verify", "/normalize", "/normalize/parquet", "/normalize/csv"):
            return self.reply(404, {"error": "not_found"})
        try:
            expected = runtime_token()
        except RuntimeError:
            return self.reply(503, {"error": "worker_authentication_unavailable"})
        if expected:
            import hmac
            if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + expected):
                return self.reply(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                return self.reply(413, {"error": "invalid_body_size"})
            raw = self.rfile.read(length)
            if self.path == "/normalize/parquet":
                import pyarrow.parquet as pq
                table = pq.read_table(io.BytesIO(raw))
                data = {"records": table.to_pylist(), "source_id": self.headers.get("X-Source-Id"), "source_version": self.headers.get("X-Source-Version")}
            elif self.path == "/normalize/csv":
                data = {"records": list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))), "source_id": self.headers.get("X-Source-Id"), "source_version": self.headers.get("X-Source-Version")}
            else:
                data = json.loads(raw, parse_float=Decimal, parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("non-finite number")),
                                  object_pairs_hook=database_unique_object if self.path == "/v7/database-assessment" else dict)
            if self.path == "/v7/database-assessment":
                result = evaluate_database(data)
            elif self.path == "/v4/capacity":
                result = evaluate_capacity(data)
            elif self.path == "/v3/normalize":
                result = normalize_v3(data)
            elif self.path == "/v3/evaluate" or (self.path == "/v2/evaluate" and str(data.get("schema_version")) == "3"):
                result = evaluate_v3(data)
            else:
                result = normalize(data) if self.path.startswith("/normalize") else evaluate_v2(data) if self.path == "/v2/evaluate" else evaluate(data)
            self.reply(200, result)
        except (EvidenceError, ValueError, TypeError, KeyError, UnicodeError):
            self.reply(422, {"error": "invalid_evidence", "message": "Invalid or incomplete evidence; check exact decimal strings, intervals, identities and source version."})
        except Exception:
            self.reply(500, {"error": "worker_error"})


if __name__ == "__main__":
    runtime_token()  # Fail before opening a socket; diagnostic contains no secret.
    ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8000"))), Handler).serve_forever()
