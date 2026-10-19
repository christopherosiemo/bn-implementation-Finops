"""Private commitment analysis only; no cloud, purchase, execution or ledger API."""
import hmac
import json
import os
import re
import socket
import ssl
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .portfolio import EvidenceError, evaluate

MAX_BODY = 32 * 1024 * 1024
MAX_RESULT = 2 * 1024 * 1024
TOKEN_FILE = "/run/secrets/commitment-portfolio-model-token"
CERT_FILE = "/run/tls/commitment-portfolio/tls.crt"
KEY_FILE = "/run/tls/commitment-portfolio/tls.key"


def regular_file(path, minimum, maximum, private=False):
    before = os.lstat(path)
    permissions = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or permissions & (0o137 if private else 0o133) or not minimum <= before.st_size <= maximum:
        raise RuntimeError("PORTFOLIO_MODEL_FILE_CONFIGURATION_REFUSED")
    with open(path, "rb") as file:
        actual = os.fstat(file.fileno())
        if (actual.st_dev, actual.st_ino, actual.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise RuntimeError("PORTFOLIO_MODEL_FILE_CONFIGURATION_REFUSED")
        raw = file.read(maximum + 1)
    if len(raw) != before.st_size:
        raise RuntimeError("PORTFOLIO_MODEL_FILE_CONFIGURATION_REFUSED")
    return raw


def load_token():
    raw = regular_file(TOKEN_FILE, 32, 4097).rstrip(b"\n")
    if not 32 <= len(raw) <= 4096 or any(value < 33 or value > 126 for value in raw):
        raise RuntimeError("PORTFOLIO_MODEL_TOKEN_CONFIGURATION_REFUSED")
    return raw


def listener_configuration():
    mode = os.getenv("COMMITMENT_PORTFOLIO_MODEL_MODE", "HOSTED_TLS")
    if mode == "LOCAL_PRIVATE":
        if os.path.lexists(CERT_FILE) or os.path.lexists(KEY_FILE):
            raise RuntimeError("PORTFOLIO_MODEL_PLAINTEXT_WITH_TLS_FILES_REFUSED")
        return 8000, None
    if mode != "HOSTED_TLS":
        raise RuntimeError("PORTFOLIO_MODEL_MODE_REFUSED")
    regular_file(CERT_FILE, 1, 65536)
    regular_file(KEY_FILE, 1, 65536, private=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    # Non-root with all capabilities dropped. The private Service publishes
    # port443 to this actual TLS listener; no plaintext443 port translation.
    return 8443, context


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("duplicate object member")
        value[key] = item
    return value


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(35)

    def log_message(self, *_):
        pass

    def reply(self, status, value):
        raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_RESULT:
            status, raw = 422, b'{"error":"PORTFOLIO_RESULT_LIMIT"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(200 if self.path == "/healthz" else 404, {"status": "ok"} if self.path == "/healthz" else {"error": "NOT_FOUND"})

    def do_POST(self):
        if self.path != "/v5/commitment-portfolio":
            return self.reply(404, {"error": "NOT_FOUND"})
        try:
            authorization = self.headers.get("Authorization", "").encode("ascii")
        except UnicodeEncodeError:
            return self.reply(401, {"error": "UNAUTHENTICATED"})
        if not hmac.compare_digest(authorization, b"Bearer " + self.server.model_token):
            return self.reply(401, {"error": "UNAUTHENTICATED"})
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[1-9][0-9]{0,9}", lengths[0]) or self.headers.get("Transfer-Encoding"):
                return self.reply(413, {"error": "BODY_LIMIT"})
            length = int(lengths[0])
            if length > MAX_BODY:
                return self.reply(413, {"error": "BODY_LIMIT"})
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise EvidenceError("truncated input")
            value = json.loads(raw, object_pairs_hook=unique_object, parse_float=lambda _: (_ for _ in ()).throw(EvidenceError("decimal strings required")), parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("finite values required")))
            self.reply(200, evaluate(value))
        except (EvidenceError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, RecursionError):
            self.reply(422, {"error": "PORTFOLIO_EVIDENCE_UNSUPPORTED"})
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return


def serve():
    token = load_token()
    port, context = listener_configuration()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.model_token = token
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    try:
        serve()
    except (OSError, RuntimeError, ValueError):
        raise SystemExit("PORTFOLIO_MODEL_STARTUP_REFUSED")
