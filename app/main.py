import os
import asyncio
import time
import requests
import uuid
import secrets
import hashlib
import base64
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from dotenv import load_dotenv
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from jose import jwt  # id_token のデコードに使用

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=True)
# ================= 設定セクション =================
TENANT_DOMAIN = os.getenv("TENANT_DOMAIN")  
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
BACKEND_CLIENT_ID = os.getenv("BACKEND_CLIENT_ID")

AUTHORITY = f"https://{TENANT_DOMAIN}/{TENANT_ID}"
AUTH_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/token"
DISCOVERY_URL = f"{AUTHORITY}/.well-known/openid-configuration"

SCOPE_FOR_LOGIN = f"email offline_access openid profile api://{CLIENT_ID}/access_as_user"
SCOPE_FOR_OBO = f"api://{BACKEND_CLIENT_ID}/access_as_user"

# ログアウト後の戻り先 URL (Entra ID の管理画面で「フロントチャネル ログアウト URL」等に登録が必要な場合があります)
POST_LOGOUT_REDIRECT_URI = "http://localhost:5000"
# =================================================


def generate_pkce_pair():
    """PKCE用の verifier と challenge を生成する"""
    # 1. code_verifier: 43〜128文字のランダム文字列
    verifier = secrets.token_urlsafe(64)
    
    # 2. code_challenge: verifierをSHA256ハッシュ化 -> Base64URLエンコード
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').replace('=', '')
    
    return verifier, challenge

def verify_token(token: str, audience: str):
    """
    jwt の検証を行う関数
     - 署名検証に失敗した場合は例外を投げる
     - 検証する要素は以下
        - 署名
        - aud (Audience)
        - exp (Expiration Time)
    """
    try:
        # 1. Microsoft の公開鍵(JWKS)エンドポイントを取得
        config = requests.get(DISCOVERY_URL).json()
        jwks_uri = config.get("jwks_uri")
        jwks = requests.get(jwks_uri).json()

        # 2. トークンのヘッダーから kid (Key ID) を取得
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # 3. JWKS から一致する公開鍵を探す
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                break
        
        if not rsa_key:
            raise Exception("Public key not found.")

        # 4. 署名の検証を実行
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=CLIENT_ID, # 自身のClientID宛かチェック
            options={"verify_at_hash": False}
        )
        if payload.get("aud") != audience:
            raise Exception("Audience mismatch")
        if payload.get("exp") < time.time():
            raise Exception("Token has expired")
        return token
    except Exception as e:
        print(f"Token Verification Failed: {str(e)}")
        return None

@app.route("/")
def index():
    user_name = session.get("user_name")
    user_id_token = session.get("user_id_token")
    user_access_token = session.get("user_access_token")
    return render_template("index.html", user_name=user_name, user_id_token=user_id_token, user_access_token=user_access_token)

@app.route("/login")
def login():
    nonce = secrets.token_urlsafe(32)
    state = str(uuid.uuid4())
    
    # PKCE ペアの生成
    code_verifier, code_challenge = generate_pkce_pair()
    
    # 検証用にすべてセッションに保存
    session["auth_nonce"] = nonce
    session["auth_state"] = state
    session["code_verifier"] = code_verifier 

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": url_for("authorized", _external=True),
        "response_mode": "query",
        "scope": SCOPE_FOR_LOGIN,
        "state": state,
        "nonce": nonce,
        # PKCE パラメータを追加
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    auth_url = f"{AUTH_ENDPOINT}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return redirect(auth_url)

@app.route("/getAToken")
def authorized():
    # state の検証
    if request.args.get("state") != session.get("auth_state"):
        return "State mismatch error", 400

    code = request.args.get("code")
    if not code:
        error_msg = request.args.get("error_description")
        return f"Authorization code missing: {error_msg}", 400

    # トークン交換リクエストの構築
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": url_for("authorized", _external=True),
        "client_secret": CLIENT_SECRET,
        # PKCE: 生の verifier を送る
        "code_verifier": session.get("code_verifier")
    }
    
    resp_json = requests.post(TOKEN_ENDPOINT, data=data).json()
    
    if "error" in resp_json:
        return jsonify(resp_json), 400

    # nonce の検証
    id_token = resp_json.get("id_token")
    try:
        id_claims = jwt.get_unverified_claims(id_token)
        if id_claims.get("nonce") != session.get("auth_nonce"):
            return "Nonce validation failed", 400
        session["user_name"] = id_claims.get("name", "Unknown User")
    except Exception as e:
        return f"id_token error: {str(e)}", 400

    # id_tokenのjwt検証
    try:
        verified_id_token = verify_token(id_token, CLIENT_ID)
        session["user_id_token"] = verified_id_token
    except Exception as e:
        return f"id_token verification failed: {str(e)}", 400

    # access_tokenのjwt検証
    try:
        verified_access_token = verify_token(resp_json.get("access_token"), CLIENT_ID)
        session["user_access_token"] = verified_access_token
    except Exception as e:
        return f"access_token verification failed: {str(e)}", 400

    # 使い終わった一時情報を削除
    session.pop("auth_nonce", None)
    session.pop("auth_state", None)
    session.pop("code_verifier", None)
    
    return redirect(url_for("index"))

@app.route("/call-mcp")
async def call_mcp():
    """
    1. Entra External ID から OBO トークンを取得
        - ここでは、ユーザーアクセストークンを assertion として、MCP用の OBO トークンを取得します
    2. MCP SSEエンドポイントに接続する際に、Authorizationヘッダーに Bearer {MCP用OBOトークン} を付与して接続
    3. ツール呼び出しのレスポンスを返す
    """
    obo_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": session.get("user_access_token"),
        "requested_token_use": "on_behalf_of",
        "scope": SCOPE_FOR_OBO,
    }
    obo_resp = requests.post(TOKEN_ENDPOINT, data=obo_data).json()
    if "error" in obo_resp: return jsonify(obo_resp), 400
    mcp_access_token = obo_resp.get("access_token")
    print(f"Obtained OBO token for MCP: {mcp_access_token}")

    mcp_server_url = f"http://localhost:8000/mcp"
    
    # 4. SSE 接続の確立
    async with Client(
        mcp_server_url,
        auth=BearerAuth(mcp_access_token),
    ) as client:
        result = await client.call_tool("get_secure_data")
        print("Tool call result:", result)
        # ツールの呼び出し
        content_text = ""
        for item in result.content:
            content_text += str(item)

        return jsonify({
            "status": "success",
            "mcp_response": content_text
        })

@app.route("/logout")
def logout():
    # 1. Flask アプリ側のセッションをクリア
    session.clear()

    # 2. Entra ID の共通ログアウトエンドポイントを構築
    # post_logout_redirect_uri を指定すると、Entra ID でのログアウト後にアプリに戻ってこれます
    logout_url = (
        f"https://sawadysso.ciamlogin.com/{TENANT_ID}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={POST_LOGOUT_REDIRECT_URI}"
    )
    
    # 3. Entra ID のログアウト画面へ飛ばす
    return redirect(logout_url)

if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)