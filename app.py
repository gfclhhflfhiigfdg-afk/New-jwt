import time
import json
import base64

import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES

from google.protobuf import json_format
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from google.protobuf.message import Message

# ============================================================
#  PART 1 — LoginReq / LoginRes proto (inlined)
# ============================================================
_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0e\x46reeFire.proto"c\n\x08LoginReq\x12\x0f\n\x07open_id\x18\x16 \x01(\t'
    b'\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0blogin_token\x18\x1d '
    b'\x01(\t\x12\x1b\n\x13orign_platform_type\x18\x63 \x01(\t"]\n\x10\x42lacklist'
    b'InfoRes\x12\x1e\n\nban_reason\x18\x01 \x01(\x0e\x32\n.BanReason\x12\x17\n'
    b'\x0f\x65xpire_duration\x18\x02 \x01(\r\x12\x10\n\x08\x62\x61n_time\x18\x03 '
    b'\x01(\r"f\n\x0eLoginQueueInfo\x12\r\n\x05\x61llow\x18\x01 \x01(\x08\x12'
    b'\x16\n\x0equeue_position\x18\x02 \x01(\r\x12\x16\n\x0eneed_wait_secs\x18'
    b'\x03 \x01(\r\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08"\xa0\x03\n\x08'
    b'LoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x04\x12\x13\n\x0block_region'
    b'\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_'
    b'region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t'
    b'\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\x19\n\x11recommend_'
    b'regions\x18\x07 \x03(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl'
    b'\x18\t \x01(\r\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mul'
    b'ator_score\x18\x0b \x01(\r\x12$\n\tblacklist\x18\x0c \x01(\x0b\x32\x11.'
    b'BlacklistInfoRes\x12#\n\nqueue_info\x18\r \x01(\x0b\x32\x0f.LoginQueue'
    b'Info\x12\x0e\n\x06tp_url\x18\x0e \x01(\t\x12\x15\n\rapp_server_id\x18'
    b'\x0f \x01(\r\x12\x0f\n\x07\x61no_url\x18\x10 \x01(\t\x12\x0f\n\x07ip_city'
    b'\x18\x11 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x12 \x01(\t*\xa8\x01\n'
    b'\tBanReason\x12\x16\n\x12\x42\x41N_REASON_UNKNOWN\x10\x00\x12\x1b\n\x17'
    b'\x42\x41N_REASON_IN_GAME_AUTO\x10\x01\x12\x15\n\x11\x42\x41N_REASON_'
    b'REFUND\x10\x02\x12\x15\n\x11\x42\x41N_REASON_OTHERS\x10\x03\x12\x16\n'
    b'\x12\x42\x41N_REASON_SKINMOD\x10\x04\x12 \n\x1b\x42\x41N_REASON_IN_GAME'
    b'_AUTO_NEW\x10\xf6\x07\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "FreeFire_pb2", _globals)

LoginReq = _globals["LoginReq"]
LoginRes = _globals["LoginRes"]

# ============================================================
#  PART 2 — Settings & Crypto
# ============================================================
MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV  = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
RELEASEVERSION = "OB55"
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"

LOGIN_URL   = "https://loginbp.ppmainecoonghj.com/MajorLogin"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"

HTTP_LIMITS  = httpx.Limits(max_keepalive_connections=20, max_connections=50)
HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_http = httpx.Client(limits=HTTP_LIMITS, timeout=HTTP_TIMEOUT, verify=False)

def pad(text: bytes) -> bytes:
    n = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([n] * n)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))

def json_to_proto(json_data: dict, proto_message: Message) -> bytes:
    json_format.ParseDict(json_data, proto_message)
    return proto_message.SerializeToString()

# ============================================================
#  PART 2.5 — Free Fire nickname decoder
# ============================================================
def decode_ff_name(b64_str: str) -> str:
    """Decodes FF's XOR-obfuscated nickname from JWT."""
    try:
        if not b64_str:
            return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted = bytes(
            byte ^ key[i % len(key)]
            for i, byte in enumerate(encrypted_bytes)
        )
        return decrypted.decode("utf-8", errors="ignore")
    except Exception:
        return ""

# ============================================================
#  PART 3 — Step 1: access_token → open_id
# ============================================================
def resolve_open_id(access_token: str):
    """Uses Garena token inspect endpoint → (open_id, platform_type, error)."""
    try:
        r = _http.get(
            INSPECT_URL,
            params={"token": access_token},
            headers={
                "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
                "Accept": "application/json",
            },
        )
        if r.status_code != 200:
            return None, None, f"Inspect HTTP {r.status_code}: {r.text[:200]}"

        data = r.json()
        open_id = data.get("open_id")
        if not open_id:
            return None, None, f"No open_id in inspect response: {data}"

        platform = (
            data.get("platform")
            or data.get("login_platform")
            or data.get("main_active_platform")
            or 4
        )
        return open_id, int(platform), None
    except Exception as e:
        return None, None, f"Inspect exception: {e}"

# ============================================================
#  PART 4 — Step 2: MajorLogin → JWT
# ============================================================
def try_parse_login_res(data: bytes):
    try:
        msg = LoginRes()
        msg.ParseFromString(data)
        if msg.account_id and msg.account_id > 0:
            return json.loads(json_format.MessageToJson(msg))
    except Exception:
        pass
    return None

def extract_login_res(raw: bytes) -> dict:
    parsed = try_parse_login_res(raw)
    if parsed:
        return parsed

    idx = 0
    while True:
        idx = raw.find(b"\x08", idx)
        if idx == -1:
            break
        parsed = try_parse_login_res(raw[idx:])
        if parsed:
            return parsed
        idx += 1

    jwt_marker = raw.find(b"eyJhbGciOiJIUzI1NiIs")
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 300, -1), -1):
            if raw[i] == 0x42:
                parsed = try_parse_login_res(raw[i:])
                if parsed:
                    return parsed
                break

    raise Exception("Could not parse LoginRes from server response")

def decode_jwt_payload(jwt_token: str) -> dict:
    try:
        parts = jwt_token.split(".")
        if len(parts) >= 2:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        pass
    return {}

def major_login(access_token: str, open_id: str, platform_type: int = 4):
    """Calls MajorLogin with LoginReq proto → parsed LoginRes dict."""
    body = {
        "open_id":             open_id,
        "open_id_type":        str(platform_type),
        "login_token":         access_token,
        "orign_platform_type": str(platform_type),
    }
    proto_bytes = json_to_proto(body, LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    headers = {
        "User-Agent":      USERAGENT,
        "Accept":          "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv":         str(int(time.time())),
        "Authorization":   "Bearer",
        "X-Ga":            "v1 1",
        "Releaseversion":  RELEASEVERSION,
        "Content-Type":    "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "PlAy_VeR":        "1.132.1",
        "Ob_VeR":          RELEASEVERSION,
    }

    r = _http.post(LOGIN_URL, data=payload, headers=headers)
    if r.status_code != 200:
        raise Exception(f"MajorLogin HTTP {r.status_code}: {r.text[:200]}")

    return extract_login_res(r.content)

# ============================================================
#  PART 5 — High-level pipeline
# ============================================================
def access_token_to_jwt(access_token: str) -> dict:
    start = time.time()

    # Step 1: access_token → open_id
    open_id, platform_type, err = resolve_open_id(access_token)
    if err:
        raise Exception(f"Step1 (open_id) failed: {err}")

    # Step 2: MajorLogin → JWT
    msg = major_login(access_token, open_id, platform_type)
    jwt_token  = msg.get("token", "")
    account_id = msg.get("accountId")
    server_url = msg.get("serverUrl", "")
    region     = msg.get("lockRegion") or msg.get("notiRegion")

    if not jwt_token:
        raise Exception(f"MajorLogin returned no JWT: {msg}")

    # Decode JWT for extra fields
    decoded = decode_jwt_payload(jwt_token)
    if not account_id and decoded.get("account_id"):
        account_id = decoded["account_id"]
    if not region and decoded.get("lock_region"):
        region = decoded["lock_region"]

    # Nickname decode
    raw_nickname = decoded.get("nickname", "")
    account_name = decode_ff_name(raw_nickname)

    if not account_name or "Error" in account_name:
        import urllib.parse
        account_name = urllib.parse.unquote(raw_nickname) or "N/A"

    return {
        "status":       "success",
        "access_token": access_token,
        "open_id":      open_id,
        "account_id":   str(account_id) if account_id else "N/A",
        "account_name": account_name,
        "region":       region or "N/A",
        "platform":     platform_type,
        "server_url":   server_url or "N/A",
        "token":        jwt_token,
        "time":         f"{time.time() - start:.2f}s",
    }

# ============================================================
#  PART 6 — Flask API
# ============================================================
app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status":      "online",
        "version":     RELEASEVERSION,
        "description": "Access Token → JWT generator",
        "endpoints": {
            "/token": {
                "methods": ["GET", "POST"],
                "params":  {"access_token": "Your valid Garena access token"},
                "example_GET":  "/token?access_token=YOUR_TOKEN",
                "example_POST": {"access_token": "YOUR_TOKEN"},
            }
        }
    }), 200

@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    access_token = None
    if request.is_json and request.json:
        access_token = request.json.get("access_token")
    if not access_token:
        access_token = request.args.get("access_token")
    if not access_token and request.form:
        access_token = request.form.get("access_token")

    if not access_token or not access_token.strip():
        return jsonify({
            "status":  "error",
            "message": "access_token parameter is required",
            "usage":   "/token?access_token=YOUR_TOKEN",
        }), 400

    try:
        result = access_token_to_jwt(access_token.strip())
        return jsonify(result), 200
    except Exception as e:
        return jsonify({
            "status":  "error",
            "message": str(e),
        }), 500

