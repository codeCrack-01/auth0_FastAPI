from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import os

from urllib.parse import quote_plus, urlencode
from auth_logic import oauth, get_current_user, login_required

# Create auth router
auth = FastAPI()
secret_key = os.environ['SECRET_KEY']

templates = Jinja2Templates(directory="templates")

@auth.get("/login")
async def login(request: Request):
    """
    Login route - redirects to Auth0 login page
    """
    # Get the next URL to redirect after login
    next_url = request.query_params.get("next", "/")

    # Store the next URL in the session
    request.session["next_url"] = next_url

    # Redirect to Auth0 login
    redirect_uri = f"{request.base_url}callback"
    return await oauth.auth0.authorize_redirect(request, redirect_uri) #type: ignore

@auth.get("/callback")
async def callback(request: Request):
    """
    Callback route - called by Auth0 after login
    """
    # Get the access token
    token = await oauth.auth0.authorize_access_token(request) #type: ignore

    # Get the user info
    user = token.get("userinfo")

    # Store the user in the session
    if user:
        request.session["user"] = dict(user)

    # Redirect to the next URL
    next_url = request.session.pop("next_url", "/")
    return RedirectResponse(url=next_url)

@auth.get("/logout")
async def logout(request: Request):
    """
    Logout route - clears the session and redirects to Auth0 logout
    """
    # Clear the session
    request.session.clear()

    # Redirect to Auth0 logout
    return RedirectResponse(
        url=f"https://{os.environ.get('AUTH0_DOMAIN')}/v2/logout?" +
        urlencode(
            {
                "returnTo": f"{request.base_url}",
                "client_id": os.environ.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@auth.get("/profile")
async def profile(request: Request, user=Depends(get_current_user)):
    """
    Profile route - shows the user profile
    """
    return templates.TemplateResponse(
        "profile.html", {"request": request, "user": user}
    )

@auth.get("/")
@login_required
async def protected(request: Request):
    """
    Protected route - requires authentication
    """
    user = request.session.get("user")
    return templates.TemplateResponse(
        "index.html", {"request": request, "user": user}
    )
