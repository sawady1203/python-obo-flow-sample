import asyncio
import time
import requests
from fastmcp import FastMCP
from mcp.server.fastmcp.utilities.logging import get_logger
from fastmcp.server.dependencies import get_http_request, get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.exceptions import ToolError
from starlette.requests import Request
from jose import jwt
from dotenv import load_dotenv
import os

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=True)

logger = get_logger("FastMCP.Server")

CLIENT_ID = os.getenv("CLIENT_ID")
TENANT_DOMAIN = os.getenv("TENANT_DOMAIN")  
TENANT_ID = os.getenv("TENANT_ID")
AUTHORITY = f"https://{TENANT_DOMAIN}/{TENANT_ID}"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
DISCOVERY_URL = f"{AUTHORITY}/.well-known/openid-configuration"

class UserAuthMiddleware(Middleware):
    def __init__(self, client_id: str):
        self.client_id = client_id

    async def on_call_tool(self, context: MiddlewareContext, call_next):

        headers = get_http_headers()

        authorization_header = headers.get("Authorization")
        if not authorization_header:
            # no token -> unauthorized
            raise ToolError("Access denied: private tool")

        if not authorization_header.startswith("Bearer "):
            raise ToolError("Access denied: invalid token format")
        
        token = authorization_header.removeprefix("Bearer ").strip()

        user_id = await self.verify_token(token, self.client_id)
        if not user_id:
            raise ToolError("Access denied: private tool")
        # Middleware stores user info in context state
        context.fastmcp_context.set_state("user_id", user_id)

        return await call_next(context)

    async def verify_token(self, token: str, audience: str):
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
                audience=self.client_id, # 自身のClientID宛かチェック
                options={"verify_at_hash": False}
            )
            if payload.get("aud") != audience:
                raise ToolError("Audience mismatch")
            if payload.get("exp") < time.time():
                raise ToolError("Token has expired")
            return token
        except Exception as e:
            print(f"Token Verification Failed: {str(e)}")
            raise ToolError("Access denied: invalid token")

mcp = FastMCP("get_secure_data")
mcp.add_middleware(UserAuthMiddleware(client_id=CLIENT_ID))

@mcp.tool("get_secure_data", description="認証とセッション接続に成功したことを確認するためのツール")
def get_secure_data():
    request: Request = get_http_request()
    authorization_header = request.headers.get("Authorization")
    logger.info(f"Authorization header: {authorization_header}")

    response_data = {
        "message": "認証とセッション接続に成功しました！",
        "timestamp": time.time()
    }

    return response_data

def main():
    logger.info('start main...')
    # FastMCP docs: transport="http" + host/port
    # Server endpoint will be: http://localhost:8000/mcp
    mcp.run(transport="streamable-http", host="localhost", port=8000)

if __name__ == "__main__":
    main()