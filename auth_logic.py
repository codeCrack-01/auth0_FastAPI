from functools import wraps
import os
from urllib.parse import quote_plus

from authlib.integrations.starlette_client import OAuth
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# Auth0 configuration
oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.environ.get("AUTH0_CLIENT_ID", ""),
    client_secret=os.environ.get("AUTH0_CLIENT_SECRET", ""),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{os.environ.get("AUTH0_DOMAIN", "")}'
    f'/.well-known/openid-configuration',
)

# Helper function to check if user is logged in
def is_authenticated(request: Request) -> bool:
    """
    Check if the user is authenticated
    """
    return request.session.get("user") is not None

# Decorator to require authentication
def login_required(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        if not is_authenticated(request):
            return RedirectResponse(
                url=f"/login?next={quote_plus(str(request.url))}"
            )
        return await func(request, *args, **kwargs)
    return wrapper

# Dependency to get current user
def get_current_user(request: Request):
    """
    Get the current user from the session
    """
    user = request.session.get("user")
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user

# Function to setup Auth0 in the FastAPI app
def setup_auth(app):
    """
    Setup Auth0 for the FastAPI app
    """
    # Add session middleware if not already added
    if not any(isinstance(m, SessionMiddleware) for m in app.user_middleware):
        secret_key = os.environ.get("SESSION_SECRET_KEY", "")
        if not secret_key:
            import secrets
            secret_key = secrets.token_hex(16)
            print("WARNING: SESSION_SECRET_KEY not set, using a random one")
        app.add_middleware(SessionMiddleware, secret_key=secret_key)

    # Initialize OAuth
    # oauth.init_app(app)
