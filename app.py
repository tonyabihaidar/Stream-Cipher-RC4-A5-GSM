"""EECE 455 Project 9: Flask application for the Stream Cipher Laboratory.

Run with ``python app.py`` and open http://127.0.0.1:5000.

All cryptographic work is stateless. Plaintext and keys are not stored, and request bodies
are not logged.
"""

from __future__ import annotations

import logging
import mimetypes

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from algorithms.encoding_utils import InputValidationError
from services.cipher_service import MAX_DIRECT_BYTES, decrypt, encrypt
from services.examples import get_examples
from services.trace_service import (
    DEFAULT_PAGE_STEPS,
    MAX_PAGE_STEPS,
    MAX_TRACE_A51_BYTES,
    MAX_TRACE_RC4_BYTES,
    build_visualization,
    simplified_rc4,
)

# The Windows registry can map .js to text/plain, which makes browsers refuse ES modules.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")

MAX_REQUEST_BYTES = 1024 * 1024
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

logger = logging.getLogger(__name__)


def _json_body() -> dict:
    """Read the JSON request body. Malformed bodies become a clean 400 or 415."""
    payload = request.get_json()
    if not isinstance(payload, dict):
        raise InputValidationError("The request body must be a JSON object.")
    return payload


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    @app.after_request
    def add_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if request.path.startswith("/api/"):
            # Responses can contain plaintext, so they should not sit in a browser cache.
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(InputValidationError)
    def handle_validation_error(error: InputValidationError):
        return jsonify(error={"code": "invalid_input", "message": error.message, "field": error.field}), 400

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        messages = {
            400: "The request could not be read. Send a valid JSON object.",
            404: "That address does not exist.",
            405: "That method is not allowed for this address.",
            413: f"The request is too large. The limit is {MAX_REQUEST_BYTES // 1024} KiB.",
            415: "Send the request as JSON, with the Content-Type application/json.",
        }
        message = messages.get(error.code, "The request could not be completed.")
        return jsonify(error={"code": error.name.lower().replace(" ", "_"), "message": message, "field": None}), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        # The exception type alone is logged, so request data cannot reach the log.
        logger.error("Unexpected %s while handling %s", type(error).__name__, request.path)
        return jsonify(error={"code": "internal_error", "message": "Something went wrong on the server.", "field": None}), 500

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", algorithms=["rc4", "a51"])

    @app.get("/api/limits")
    def limits():
        return jsonify(
            direct_bytes=MAX_DIRECT_BYTES,
            trace_rc4_bytes=MAX_TRACE_RC4_BYTES,
            trace_a51_bytes=MAX_TRACE_A51_BYTES,
            default_page_steps=DEFAULT_PAGE_STEPS,
            max_page_steps=MAX_PAGE_STEPS,
        )

    @app.get("/api/examples")
    def examples():
        return jsonify(examples=get_examples())

    @app.post("/api/encrypt")
    def api_encrypt():
        return jsonify(encrypt(_json_body()))

    @app.post("/api/decrypt")
    def api_decrypt():
        return jsonify(decrypt(_json_body()))

    @app.post("/api/visualize")
    def api_visualize():
        return jsonify(build_visualization(_json_body()))

    @app.post("/api/simplified-rc4")
    def api_simplified_rc4():
        return jsonify(simplified_rc4(_json_body()))

    return app


app = create_app()


if __name__ == "__main__":
    print("EECE 455 Stream Cipher Laboratory: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
