# ============================================================
#   ZESTY  —  Garena Register API (proxy)
#   /guest/register  +  /guest/token/grant
#   OB55  |  HMAC-signed server-side
# ============================================================

from flask import Flask, request, jsonify
import requests, hmac, hashlib, json, string, random, os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ============================================================
#                     CONSTANTS
# ============================================================
API_SECRET_KEY = os.getenv(
    "GARENA_SECRET",
    "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
)
API_HEX_KEY = API_SECRET_KEY
APP_ID      = 100067

REGISTER_URL = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
TOKEN_URL    = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
HOST         = "100067.connect.garena.com"

DEFAULT_UA = "GarenaMSDK/4.0.44(25028RN03A ;Android 15;ar;EG;app 1.132.1 2019121229;)"
ALLOWED_UA_OVERRIDE = True  # set False to force DEFAULT_UA always

# ============================================================
#                     HELPERS
# ============================================================
def _sign(body_bytes: bytes) -> str:
    return hmac.new(API_SECRET_KEY.encode(), body_bytes, hashlib.sha256).hexdigest()

def _build_headers(ua: str, signature: str) -> dict:
    return {
        "User-Agent": ua,
        "Connection": "Keep-Alive",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Authorization": f"Signature {signature}",
        "Content-Type": "application/json; charset=utf-8",
        "Host": HOST,
    }

def _pick_ua() -> str:
    if ALLOWED_UA_OVERRIDE:
        incoming = request.headers.get("User-Agent", "").strip()
        if incoming.startswith("GarenaMSDK/"):
            return incoming
    return DEFAULT_UA

def _gen_password() -> str:
    return f"Zesty{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

def _json_response(content: bytes, status: int):
    return app.response_class(content, status=status, mimetype="application/json")

# ============================================================
#               POST /guest/register
# ============================================================
@app.route("/guest/register", methods=["POST"])
def guest_register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid json body"}), 400

    password = data.get("password") or _gen_password()

    # Only fields that matter — ignore any client-supplied junk
    payload = {
        "app_id":      APP_ID,
        "client_type": 2,
        "password":    password,
        "source":      2,
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature  = _sign(body_bytes)
    headers    = _build_headers(_pick_ua(), signature)

    try:
        r = requests.post(
            REGISTER_URL,
            headers=headers,
            data=body_bytes,
            timeout=10,
            verify=False,
        )
        # Pass through Garena's exact body + status
        return _json_response(r.content, r.status_code)
    except requests.exceptions.Timeout:
        return jsonify({"error": "upstream timeout"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"upstream error: {e.__class__.__name__}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
#               POST /guest/token/grant
# ============================================================
@app.route("/guest/token/grant", methods=["POST"])
def guest_token_grant():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid json body"}), 400

    uid      = data.get("uid")
    password = data.get("password")
    device_id = data.get("device_id") or "02-344afb0e-593c-40b7-92f2-171972f74807"

    if not uid or not password:
        return jsonify({"error": "uid and password are required"}), 400

    payload = {
        "client_id":     APP_ID,
        "client_secret": API_HEX_KEY,
        "client_type":   2,
        "device_id":     device_id,
        "password":      password,
        "response_type": "token",
        "uid":           uid,
    }
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature  = _sign(body_bytes)
    headers    = _build_headers(_pick_ua(), signature)

    try:
        r = requests.post(
            TOKEN_URL,
            headers=headers,
            data=body_bytes,
            timeout=10,
            verify=False,
        )
        return _json_response(r.content, r.status_code)
    except requests.exceptions.Timeout:
        return jsonify({"error": "upstream timeout"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"upstream error: {e.__class__.__name__}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
#               HEALTH / INFO
# ============================================================
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "zesty-register-api",
        "version": "OB55",
        "endpoints": [
            "POST /guest/register       {password?}",
            "POST /guest/token/grant    {uid, password, device_id?}",
        ],
    })

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "method not allowed"}), 405

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404

# ============================================================
#               SERVERLESS HANDLER (Vercel/etc)
# ============================================================
def handler(request):
    return app(request)

# ============================================================
#                     LOCAL RUN
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)