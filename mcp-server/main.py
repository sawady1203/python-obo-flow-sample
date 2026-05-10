import asyncio
import time
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier
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
AUTHORITY = f"https://{TENANT_ID}.ciamlogin.com/{TENANT_ID}"
ISSUER = f"{AUTHORITY}/v2.0"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
scopes_env = os.getenv("JWT_REQUIRED_SCOPES")
required_scopes = scopes_env.split(",") if scopes_env else []

verifier = JWTVerifier(
    jwks_uri=JWKS_URL,
    issuer=ISSUER,
    audience=CLIENT_ID,
    required_scopes=required_scopes
)

mcp = FastMCP(name="get_secure_data", auth=verifier)

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