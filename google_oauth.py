import requests
from urllib.parse import urlencode

TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"

DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
]


def get_auth_url(client_id, redirect_uri, scopes=None):
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes or DEFAULT_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_code(code, client_id, client_secret, redirect_uri):
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    resp = requests.post(TOKEN_URL, data=data, timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_user_info(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(USERINFO_URL, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()
