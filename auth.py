import bcrypt
import pyotp
import jwt
import json
import os
import random
import requests
import datetime
import uuid as uuid_mod
from Crypto.PublicKey import RSA
from db import DB

db = DB("johnnyid.db")
users = db.table(
    "users",
    {
        "email": "TEXT",
        "name": "TEXT",
        "uuid": "TEXT",
        "password_hash": "TEXT",
        "twofa": "TEXT",
    },
    primary_key="email",
)
google_users = db.table(
    "google_users",
    {
        "email": "TEXT",
        "name": "TEXT",
        "uuid": "TEXT",
        "picture": "TEXT",
        "google_id": "TEXT",
        "twofa": "TEXT",
    },
    primary_key="email",
)

RSA_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_PATH = os.path.join(RSA_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(RSA_DIR, "public.pem")


def _ensure_keys():
    if os.path.exists(PRIVATE_KEY_PATH):
        return
    os.makedirs(RSA_DIR, exist_ok=True)
    key = RSA.generate(2048)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key("PEM"))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key("PEM"))


_ensure_keys()


def _load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return f.read()


def _load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read()


def sign_jwt(claims: dict, expires_minutes: int = 60) -> str:
    payload = {
        **claims,
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")


def verify_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, _load_public_key(), algorithms=["RS256"])
    except jwt.InvalidTokenError:
        return None


def create_user(email: str, password: str, name: str = "") -> bool:
    email = email.lower()
    if get_user(email) is not None:
        return False
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users.insert(
        {
            "email": email,
            "name": name,
            "uuid": str(uuid_mod.uuid4()),
            "password_hash": hashed.decode("utf-8"),
            "twofa": {"totp": None, "email": {"address": email}},
        }
    )
    return True


def verify_user(email: str, password: str) -> bool:
    user = get_user(email)
    if user is None:
        return False
    return bcrypt.checkpw(
        password.encode("utf-8"), user["password_hash"].encode("utf-8")
    )


def get_user(email: str) -> dict | None:
    return users.get(email=email.lower())


def get_user_by_uuid(user_uuid: str) -> dict | None:
    results = users.search(uuid=user_uuid)
    return results[0] if results else None


def get_enrolled_2fa_methods(email: str) -> list[str]:
    user = get_user(email)
    if user is None:
        return []
    methods = []
    for method, data in user["twofa"].items():
        if data is None:
            continue
        if method == "totp" and not data.get("verified", True):
            continue
        methods.append(method)
    return methods


def enroll_totp(email: str) -> str | None:
    user = get_user(email)
    if user is None:
        return None
    secret = pyotp.random_base32()
    twofa = user["twofa"]
    twofa["totp"] = {"secret": secret}
    users.update({"twofa": twofa}, email=user["email"])
    return secret


def enroll_email_2fa(email: str, address: str) -> bool:
    user = get_user(email)
    if user is None:
        return False
    twofa = user["twofa"]
    twofa["email"] = {"address": address}
    users.update({"twofa": twofa}, email=user["email"])
    return True


def unenroll_2fa(email: str, method: str) -> bool:
    user = get_user(email)
    if user is None or method not in ("totp", "email"):
        return False
    twofa = user["twofa"]
    twofa[method] = None
    users.update({"twofa": twofa}, email=user["email"])
    return True


def verify_totp(email: str, token: str) -> bool:
    user = get_user(email)
    if user is None or user["twofa"]["totp"] is None:
        return False
    totp = pyotp.TOTP(user["twofa"]["totp"]["secret"])
    return totp.verify(token)


def delete_user(email: str) -> bool:
    return users.remove(email=email.lower()) > 0


def get_or_create_google_user(
    email: str, name: str, picture: str, google_id: str
) -> dict | None:
    email = email.lower()
    existing = google_users.get(email=email)
    if existing is not None:
        return existing
    google_users.insert(
        {
            "email": email,
            "name": name,
            "uuid": str(uuid_mod.uuid4()),
            "picture": picture,
            "google_id": google_id,
            "twofa": {"totp": None, "email": None},
        }
    )
    return google_users.get(email=email)


def get_google_user(email: str) -> dict | None:
    return google_users.get(email=email.lower())


login_history = db.table(
    "login_history",
    {
        "id": "INTEGER",
        "user_uuid": "TEXT",
        "timestamp": "TEXT",
        "ip": "TEXT",
        "user_agent": "TEXT",
    },
    primary_key="id",
)


def record_login(user_uuid: str, ip: str, user_agent: str):
    login_history.insert(
        {
            "user_uuid": user_uuid,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ip": ip,
            "user_agent": user_agent,
        }
    )


def get_login_history(user_uuid: str) -> list[dict]:
    rows = login_history.search(user_uuid=user_uuid)
    rows.reverse()
    return rows


def change_email(old_email: str, new_email: str) -> bool:
    old_email = old_email.lower()
    new_email = new_email.lower()
    user = get_user(old_email)
    if user is None:
        return False
    if get_user(new_email) is not None:
        return False
    users.remove(email=old_email)
    users.insert({**user, "email": new_email})
    return True


def change_password(email: str, new_password: str) -> bool:
    user = get_user(email)
    if user is None:
        return False
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    users.update({"password_hash": hashed.decode("utf-8")}, email=email.lower())
    return True


pending_codes = db.table(
    "pending_codes",
    {
        "id": "INTEGER",
        "email": "TEXT",
        "code": "TEXT",
        "method": "TEXT",
        "created_at": "TEXT",
        "expires_at": "TEXT",
    },
    primary_key="id",
)


def _generate_code() -> str:
    return f"{random.randint(100000, 999999)}"


def _send_email_code(to_address: str, code: str, email: str):
    api_key = os.getenv("RESEND_API_KEY", "")
    from_addr = os.getenv("RESEND_FROM", "JohnnyID <onboarding@resend.dev>")
    base_url = os.getenv("BASE_URL", "http://localhost:5000")
    verify_url = f"{base_url}/l/2fa/verify-link?email={email}&code={code}"

    html = f"""\
<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:40px 0">
<tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:400px;background:#fff;border:1px solid #dadce0;border-radius:12px;padding:40px 32px">
<tr><td align="center" style="padding-bottom:16px">
<img src="{base_url}/static/Logo.png" width="48" height="48" style="border-radius:50%">
</td></tr>
<tr><td align="center" style="padding-bottom:24px">
<h1 style="margin:0;font-size:20px;color:#202124">JohnnyID</h1>
<p style="margin:8px 0 0;font-size:14px;color:#5f6368">Verify your identity</p>
</td></tr>
<tr><td style="padding-bottom:20px">
<p style="margin:0 0 20px;font-size:14px;color:#202124;line-height:1.5">
We noticed a sign-in attempt from a new device or location. Click the button below to verify it's you.
</p>
</td></tr>
<tr><td align="center" style="padding-bottom:24px">
<a href="{verify_url}" style="display:inline-block;background:#1a73e8;color:#ffffff;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:500">Verify identity</a>
</td></tr>
<tr><td align="center" style="padding-bottom:20px">
<p style="margin:0;font-size:13px;color:#5f6368">
Or enter this code: <strong style="color:#202124;font-size:16px;letter-spacing:0.2em">{code}</strong>
</p>
</td></tr>
<tr><td style="border-top:1px solid #dadce0;padding-top:16px">
<p style="margin:0;font-size:12px;color:#9aa0a6;line-height:1.5">
This code expires in 5 minutes. If you didn't request this, you can safely ignore this email.
</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""

    if not api_key:
        print(f"[DEV] 2FA code for {to_address}: {code}")
        print(f"[DEV] 2FA link: {verify_url}")
        return

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "from": from_addr,
                "to": [to_address],
                "subject": "JohnnyID - Verify your identity",
                "html": html,
            },
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        print(f"[FALLBACK] 2FA code for {to_address}: {code}")


def send_2fa_code(email: str) -> bool | str:
    user = get_user(email)
    if user is None:
        return False

    now = datetime.datetime.now(datetime.timezone.utc)
    rows = pending_codes.search(email=email.lower())
    for row in rows:
        created = datetime.datetime.fromisoformat(row["created_at"])
        if (now - created).total_seconds() < 60:
            remaining = 60 - int((now - created).total_seconds())
            return f"Please wait {remaining} seconds before requesting a new code."

    code = _generate_code()
    expires = now + datetime.timedelta(minutes=5)

    pending_codes.insert(
        {
            "email": email.lower(),
            "code": code,
            "method": "email",
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }
    )

    to = user["twofa"].get("email", {}).get("address", email)
    _send_email_code(to, code, email)
    return True


def verify_2fa_code(email: str, code: str) -> bool:
    email = email.lower()
    now = datetime.datetime.now(datetime.timezone.utc)
    rows = pending_codes.search(email=email)
    for row in rows:
        exp = datetime.datetime.fromisoformat(row["expires_at"])
        if row["code"] == code and exp > now:
            pending_codes.remove(id=row["id"])
            return True
    return False
