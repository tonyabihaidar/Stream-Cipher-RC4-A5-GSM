"""Isolated browser-test server; never connects to the live Firebase project.

Start the demo Auth/Firestore emulators, then run with
PYTHONPATH=. .venv/bin/python tests/browser_server.py.
"""
from pathlib import Path
import subprocess
import tempfile
from flask import Response, jsonify, request
from app import create_app

app = create_app()
test_directory = tempfile.TemporaryDirectory(prefix='eece455-browser-test-')
test_bundle = Path(test_directory.name) / 'firebase.js'
subprocess.run([
    'node_modules/.bin/esbuild', '--bundle', '--format=esm', '--minify',
    f'--outfile={test_bundle}',
], input="export * from './frontend/firebase.js'; export {connectAuthEmulator} from 'firebase/auth'; export {connectFirestoreEmulator} from 'firebase/firestore';", text=True, check=True)

@app.before_request
def test_firebase():
    if request.path == '/static/firebase-config.json':
        return jsonify(apiKey='demo-key', projectId='demo-stream-cipher', appId='demo-app', authDomain='localhost')
    if request.path == '/static/js/firebase.bundle.js':
        return Response(test_bundle.read_text(), mimetype='text/javascript')
    if request.path == '/static/js/account.js':
        source = Path('static/js/account.js').read_text().replace(
            'db = sdk.getFirestore(app);',
            "db = sdk.getFirestore(app); sdk.connectAuthEmulator(auth, 'http://127.0.0.1:9099'); sdk.connectFirestoreEmulator(db, '127.0.0.1', 8085);")
        return Response(source, mimetype='text/javascript')

# Run before create_app's after_request handler, so adjust its module constant.
import app as app_module
app_module.CONTENT_SECURITY_POLICY = app_module.CONTENT_SECURITY_POLICY.replace(
    "connect-src 'self'", "connect-src 'self' http://127.0.0.1:9099 http://127.0.0.1:8085")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=False)
