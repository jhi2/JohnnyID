import sentry_sdk  # type: ignore
from flask import *  # type: ignore
from jjwrapper import *  # type: ignore
import logging
import json
from datetime import datetime
import requests as rq
from turnstile import *  # type: ignore
from dotenv import load_dotenv  # type: ignore
from google_oauth import get_auth_url, exchange_code, get_user_info  # type: ignore
import auth  # type: ignore
import os

load_dotenv()
sentry_sdk.init(
    dsn="https://7826562e2ee5c1f03edfefa0c4caf4cf@o4510961581162496.ingest.de.sentry.io/4511114260054096",
    send_default_pii=True,
    traces_sample_rate=1.0,
    profile_session_sample_rate=1.0,
    profile_lifecycle="trace",
    enable_logs=True,
)

logger = logging.getLogger(__name__)
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")


@app.route("/")
def root():
    redirect_uri = request.args.get("redirect_uri")
    uid = request.cookies.get("uid")
    if uid:
        user = auth.get_user_by_uuid(uid)
        if user:
            auth.record_login(
                user["uuid"],
                request.remote_addr or "",
                request.headers.get("User-Agent", ""),
            )
            token = auth.sign_jwt(
                {"email": user["email"], "name": user.get("name", "")},
                expires_minutes=60,
            )
            if redirect_uri:
                separator = "&" if "?" in redirect_uri else "?"
                return redirect(f"{redirect_uri}{separator}token={token}")
            return redirect(url_for("dashboard"))
    return redirect(url_for("emailenter", redirect_uri=redirect_uri or "/"))


cpenv = create_jinja_env(template_dir="components")
devices = auth.db.table(
    "devices",
    {"id": "INTEGER", "user_agent": "TEXT", "ip": "TEXT"},
    primary_key="id",
)


@app.route("/l/email/")
def emailenter():
    redirect_uri = request.args.get("redirect_uri", "/")
    error = request.args.get("error")
    success = request.args.get("success")
    return render_template(
        "lgbase.html.j2",
        stage="Enter your email address to continue.",
        formhtml=render_component(
            cpenv,
            "email_field.html.j2",
            security_device_verify=url_for("trackdevice"),
            callbackuri=url_for("passwordenter"),
            google_oauth_endpoint=url_for("google_redir"),
            signup_endpoint=url_for("signup"),
            redirect_uri=redirect_uri,
        ),
        error=error,
        success=success,
    )


def lookup_user_agents(ip):
    return [doc["user_agent"] for doc in devices.search(ip=ip)]


def lookup_ips(user_agent):
    return [doc["ip"] for doc in devices.search(user_agent=user_agent)]


@app.route("/internal/trackdevice/", methods=["POST"])
def trackdevice():
    body = request.json
    useragents = lookup_user_agents(body["ip"])
    newua = False
    newip = False
    if body["user_agent"] not in useragents:
        newua = True
    ips = lookup_ips(body["user_agent"])
    if body["ip"] not in ips:
        newip = True
    devices.insert({"user_agent": body["user_agent"], "ip": body["ip"]})
    return jsonify({"status": "userrecorded", "newua": newua, "newip": newip})


@app.route("/l/pwd/", methods=["GET", "POST"])
def passwordenter():
    if request.method == "POST":
        email = request.form.get("username")
        newip = request.form.get("newip") == "true"
        newua = request.form.get("newua") == "true"
        redirect_uri = request.form.get("redirect_uri", "/")
        return render_template(
            "lgbase.html.j2",
            stage="Enter your password to continue.",
            formhtml=render_component(
                cpenv,
                "password_field.html.j2",
                callbackuri=url_for("login"),
                email=email,
                newip=newip,
                newua=newua,
                redirect_uri=redirect_uri,
            ),
        )
    else:
        return redirect(url_for("emailenter"))


@app.route("/l/login/", methods=["POST"])
def login():
    email = request.form.get("username")
    password = request.form.get("password")
    redirect_uri = request.form.get("redirect_uri", "/")
    turnstile_token = request.form.get("cf-turnstile-response")
    turnstile_secret = os.getenv("TURNSTILE_SECRET_KEY", "")
    if turnstile_secret:
        result = validate_turnstile(
            turnstile_token, turnstile_secret, remoteip=request.remote_addr
        )
        if not result.get("success"):
            logger.warning(f"Turnstile failed for {email}: {result.get('error-codes')}")
            return render_template(
                "lgbase.html.j2",
                stage="CAPTCHA verification failed. Please try again.",
                formhtml=render_component(
                    cpenv,
                    "password_field.html.j2",
                    callbackuri=url_for("login"),
                    email=email,
                    newip=False,
                    newua=False,
                    redirect_uri=redirect_uri,
                ),
            ), 403

    if not email or not password:
        logger.warning("Login 403: missing email or password")
        return abort(403)

    user = auth.get_user(email)
    if user is None:
        logger.warning(f"Login: no user found for {email}")
        return redirect(url_for("signup", error="No email found. Create an account?"))

    if not auth.verify_user(email, password):
        logger.warning(f"Login 403: wrong password for {email}")
        return redirect(
            url_for("emailenter", error="Wrong password", redirect_uri=redirect_uri)
        )

    newip = request.form.get("newip") == "true"
    newua = request.form.get("newua") == "true"
    methods = auth.get_enrolled_2fa_methods(email)

    if (newip or newua) and methods:
        logger.info(f"2FA required for {email} (newip={newip}, newua={newua})")
        auth.send_2fa_code(email)
        return render_template(
            "lgbase.html.j2",
            stage="Verify your identity.",
            formhtml=render_component(
                cpenv,
                "twofa_verify.html.j2",
                callbackuri=url_for("verify_2fa"),
                send_uri=url_for("send_2fa"),
                email=email,
                redirect_uri=redirect_uri,
                methods=methods,
                has_email="email" in methods,
            ),
        )

    token = auth.sign_jwt(
        {"email": user["email"], "name": user.get("name", "")},
        expires_minutes=60,
    )

    if user.get("uuid"):
        auth.record_login(
            user["uuid"],
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
        )

    separator = "&" if "?" in redirect_uri else "?"
    resp = make_response(redirect(f"{redirect_uri}{separator}token={token}"))
    if user.get("uuid"):
        resp.set_cookie(
            "uid",
            user["uuid"],
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax",
        )
    return resp


@app.route("/l/o/google/google/login/v1/")
def google_redir():
    redirect_uri = request.args.get("redirect_uri", "/")
    session["oauth_redirect_uri"] = redirect_uri
    authurl = get_auth_url(
        os.getenv("google_oauth_client_id"), url_for("google_callback", _external=True)
    )
    return redirect(authurl)


@app.route("/l/o/google/google/callback/v1/")
def google_callback():
    code = request.args.get("code")
    redirect_uri = session.pop("oauth_redirect_uri", "/")
    if code:
        try:
            tokens = exchange_code(
                code,
                os.getenv("google_oauth_client_id"),
                os.getenv("google_oauth_client_secret"),
                url_for("google_callback", _external=True),
            )
            userinfo = get_user_info(tokens["access_token"])
            user = auth.get_or_create_google_user(
                email=userinfo["email"],
                name=userinfo.get("name", ""),
                picture=userinfo.get("picture", ""),
                google_id=userinfo["sub"],
            )
            logger.info(f"Google login: {user['email']}")  # type: ignore
            token = auth.sign_jwt(
                {"email": user["email"], "name": user.get("name", "")},
                expires_minutes=60,
            )
            if user.get("uuid"):
                auth.record_login(
                    user["uuid"],
                    request.remote_addr or "",
                    request.headers.get("User-Agent", ""),
                )
            separator = "&" if "?" in redirect_uri else "?"
            resp = make_response(redirect(f"{redirect_uri}{separator}token={token}"))
            if user.get("uuid"):
                resp.set_cookie(
                    "uid",
                    user["uuid"],
                    max_age=60 * 60 * 24 * 365,
                    httponly=True,
                    samesite="Lax",
                )
            return resp
        except Exception as e:
            logger.error(f"Google OAuth callback error: {e}")
            return redirect(url_for("emailenter"))
    else:
        return redirect(url_for("emailenter"))


@app.route("/l/signup/", methods=["GET"])
def signup():
    error = request.args.get("error")
    return render_template(
        "lgbase.html.j2",
        stage="Create your account.",
        formhtml=render_component(
            cpenv,
            "signup_field.html.j2",
            callbackuri=url_for("signup"),
            login_endpoint=url_for("emailenter"),
        ),
        error=error,
    )


@app.route("/l/signup/", methods=["POST"])
def signup_post():
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm = request.form.get("confirm")

    if not name or not email or not password or not confirm:
        return render_template(
            "lgbase.html.j2",
            stage="All fields are required.",
            formhtml=render_component(
                cpenv,
                "signup_field.html.j2",
                callbackuri=url_for("signup"),
                login_endpoint=url_for("emailenter"),
            ),
        ), 400

    if password != confirm:
        return render_template(
            "lgbase.html.j2",
            stage="Passwords do not match.",
            formhtml=render_component(
                cpenv,
                "signup_field.html.j2",
                callbackuri=url_for("signup"),
                login_endpoint=url_for("emailenter"),
            ),
        ), 400

    if auth.create_user(email, password, name=name):
        auth.send_2fa_code(email)
        methods = auth.get_enrolled_2fa_methods(email)
        return render_template(
            "lgbase.html.j2",
            stage="Verify your email to finish.",
            formhtml=render_component(
                cpenv,
                "twofa_verify.html.j2",
                callbackuri=url_for("signup_verify"),
                send_uri=url_for("send_2fa"),
                email=email,
                redirect_uri=url_for("emailenter"),
                methods=methods,
                has_email="email" in methods,
            ),
            success="We sent a code to your email.",
        )
    else:
        return render_template(
            "lgbase.html.j2",
            stage="An account with that email already exists.",
            formhtml=render_component(
                cpenv,
                "signup_field.html.j2",
                callbackuri=url_for("signup"),
                login_endpoint=url_for("emailenter"),
            ),
        ), 409


@app.route("/l/signup/verify", methods=["POST"])
def signup_verify():
    email = request.form.get("email")
    code = request.form.get("code")
    if not email or not code:
        return abort(403)

    user = auth.get_user(email)
    if user is None:
        return abort(403)

    if auth.verify_2fa_code(email, code):
        return redirect(
            url_for("emailenter", success="Account created. Sign in to continue.")
        )

    methods = auth.get_enrolled_2fa_methods(email)
    return render_template(
        "lgbase.html.j2",
        stage="Verify your email to finish.",
        formhtml=render_component(
            cpenv,
            "twofa_verify.html.j2",
            callbackuri=url_for("signup_verify"),
            send_uri=url_for("send_2fa"),
            email=email,
            redirect_uri=url_for("emailenter"),
            methods=methods,
            has_email="email" in methods,
        ),
        error="Invalid or expired code.",
    )


@app.route("/l/2fa/verify-link")
def verify_2fa_link():
    email = request.args.get("email")
    code = request.args.get("code")
    if not email or not code:
        return redirect(url_for("emailenter"))

    user = auth.get_user(email)
    if user is None:
        return redirect(url_for("emailenter"))

    if auth.verify_2fa_code(email, code):
        token = auth.sign_jwt(
            {"email": user["email"], "name": user.get("name", "")},
            expires_minutes=60,
        )
        auth.record_login(
            user.get("uuid", ""),
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
        )
        resp = make_response(redirect(f"/?redirect_uri=/"))
        if user.get("uuid"):
            resp.set_cookie(
                "uid",
                user["uuid"],
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax",
            )
        return resp

    return redirect(
        url_for("emailenter", error="Verification link expired or invalid.")
    )


@app.route("/l/2fa/send", methods=["POST"])
def send_2fa():
    email = request.form.get("email")
    redirect_uri = request.form.get("redirect_uri", "/")
    if not email:
        return abort(403)
    result = auth.send_2fa_code(email)
    methods = auth.get_enrolled_2fa_methods(email)
    if isinstance(result, str):
        return render_template(
            "lgbase.html.j2",
            stage="Verify your identity.",
            formhtml=render_component(
                cpenv,
                "twofa_verify.html.j2",
                callbackuri=url_for("verify_2fa"),
                send_uri=url_for("send_2fa"),
                email=email,
                redirect_uri=redirect_uri,
                methods=methods,
                has_email="email" in methods,
            ),
            error=result,
        )
    return render_template(
        "lgbase.html.j2",
        stage="Verify your identity.",
        formhtml=render_component(
            cpenv,
            "twofa_verify.html.j2",
            callbackuri=url_for("verify_2fa"),
            send_uri=url_for("send_2fa"),
            email=email,
            redirect_uri=redirect_uri,
            methods=methods,
            has_email="email" in methods,
        ),
        success="Code sent.",
    )


@app.route("/l/2fa/verify", methods=["POST"])
def verify_2fa():
    email = request.form.get("email")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri", "/")
    if not email or not code:
        return abort(403)

    user = auth.get_user(email)
    if user is None:
        return abort(403)

    if auth.verify_2fa_code(email, code):
        token = auth.sign_jwt(
            {"email": user["email"], "name": user.get("name", "")},
            expires_minutes=60,
        )
        auth.record_login(
            user.get("uuid", ""),
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
        )
        separator = "&" if "?" in redirect_uri else "?"
        resp = make_response(redirect(f"{redirect_uri}{separator}token={token}"))
        if user.get("uuid"):
            resp.set_cookie(
                "uid",
                user["uuid"],
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax",
            )
        return resp

    methods = auth.get_enrolled_2fa_methods(email)
    return render_template(
        "lgbase.html.j2",
        stage="Verify your identity.",
        formhtml=render_component(
            cpenv,
            "twofa_verify.html.j2",
            callbackuri=url_for("verify_2fa"),
            send_uri=url_for("send_2fa"),
            email=email,
            redirect_uri=redirect_uri,
            methods=methods,
            has_email="email" in methods,
        ),
        error="Invalid or expired code.",
    )


def _get_current_user():
    uid = request.cookies.get("uid")
    if uid:
        return auth.get_user_by_uuid(uid)
    return None


@app.route("/m/dashboard/")
def dashboard():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    history = auth.get_login_history(user["uuid"])
    hour = datetime.now().hour
    if hour < 12:
        greeting = "Good morning"
    elif hour < 18:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"
    with open("data/apps.json") as f:
        apps = json.load(f)
    token = auth.sign_jwt(
        {"email": user["email"], "name": user.get("name", "")},
        expires_minutes=60,
    )
    return render_template(
        "dashboard.html.j2",
        user=user,
        history=history,
        greeting=greeting,
        apps=apps,
        token=token,
        signout_uri=url_for("signout"),
        change_email_uri=url_for("dashboard_email"),
        change_password_uri=url_for("dashboard_password"),
        totp_setup_uri=url_for("dashboard_totp_setup"),
        totp_remove_uri=url_for("dashboard_totp_remove"),
        delete_account_uri=url_for("dashboard_delete"),
        error=request.args.get("error"),
        success=request.args.get("success"),
    )


@app.route("/m/dashboard/email", methods=["POST"])
def dashboard_email():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    confirm_text = request.form.get("confirm_text")
    if confirm_text != "change email":
        return redirect(url_for("dashboard", error='Type "change email" to confirm'))
    password = request.form.get("password")
    if not password or not auth.verify_user(user["email"], password):
        return redirect(url_for("dashboard", error="Wrong password"))
    new_email = request.form.get("new_email")
    if not new_email:
        return redirect(url_for("dashboard", error="Email is required"))
    if auth.change_email(user["email"], new_email):
        resp = make_response(redirect(url_for("dashboard", success="Email updated")))
        resp.delete_cookie("uid")
        return resp
    return redirect(url_for("dashboard", error="Email already in use"))


@app.route("/m/dashboard/password", methods=["POST"])
def dashboard_password():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    confirm_text = request.form.get("confirm_text")
    if confirm_text != "change password":
        return redirect(url_for("dashboard", error='Type "change password" to confirm'))
    password = request.form.get("password")
    if not password or not auth.verify_user(user["email"], password):
        return redirect(url_for("dashboard", error="Wrong password"))
    new_password = request.form.get("new_password")
    confirm = request.form.get("confirm")
    if not new_password or not confirm:
        return redirect(url_for("dashboard", error="All fields are required"))
    if new_password != confirm:
        return redirect(url_for("dashboard", error="Passwords do not match"))
    if auth.change_password(user["email"], new_password):
        return redirect(url_for("dashboard", success="Password updated"))
    return redirect(url_for("dashboard", error="Could not update password"))


@app.route("/m/dashboard/totp/setup", methods=["POST"])
def dashboard_totp_setup():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    if user["twofa"].get("totp"):
        return redirect(url_for("dashboard", error="Authenticator already set up"))
    import pyotp  # type: ignore

    secret = pyotp.random_base32()
    otpauth_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="JohnnyID"
    )
    auth.users.update(
        {"twofa": {**user["twofa"], "totp": {"secret": secret, "verified": False}}},
        email=user["email"],
    )
    return render_template(
        "totp_setup.html.j2",
        secret=secret,
        otpauth_uri=otpauth_uri,
        verify_uri=url_for("dashboard_totp_verify"),
        cancel_uri=url_for("dashboard_totp_cancel"),
        dashboard_uri=url_for("dashboard"),
        error=None,
    )


@app.route("/m/dashboard/totp/verify", methods=["POST"])
def dashboard_totp_verify():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    code = request.form.get("code")
    if not code:
        return redirect(url_for("dashboard", error="Code is required"))
    totp_data = user["twofa"].get("totp")
    if not totp_data or not totp_data.get("secret"):
        return redirect(url_for("dashboard", error="No pending authenticator setup"))
    import pyotp  # type: ignore

    totp = pyotp.TOTP(totp_data["secret"])
    if totp.verify(code):
        auth.users.update(
            {
                "twofa": {
                    **user["twofa"],
                    "totp": {"secret": totp_data["secret"], "verified": True},
                }
            },
            email=user["email"],
        )
        return redirect(url_for("dashboard", success="Authenticator enabled"))
    return render_template(
        "totp_setup.html.j2",
        secret=totp_data["secret"],
        otpauth_uri=pyotp.totp.TOTP(totp_data["secret"]).provisioning_uri(
            name=user["email"], issuer_name="JohnnyID"
        ),
        verify_uri=url_for("dashboard_totp_verify"),
        cancel_uri=url_for("dashboard_totp_cancel"),
        dashboard_uri=url_for("dashboard"),
        error="Invalid code. Try again.",
    )


@app.route("/m/dashboard/totp/remove", methods=["POST"])
def dashboard_totp_remove():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    twofa = user["twofa"]
    twofa["totp"] = None
    auth.users.update({"twofa": twofa}, email=user["email"])
    return redirect(url_for("dashboard", success="Authenticator removed"))


@app.route("/m/dashboard/totp/cancel", methods=["POST"])
def dashboard_totp_cancel():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    twofa = user["twofa"]
    twofa.pop("totp", None)
    auth.users.update({"twofa": twofa}, email=user["email"])
    return redirect(url_for("dashboard", success="Authenticator setup cancelled"))


@app.route("/m/signout/")
def signout():
    resp = make_response(redirect(url_for("emailenter")))
    resp.delete_cookie("uid")
    return resp


@app.route("/m/dashboard/delete", methods=["POST"])
def dashboard_delete():
    user = _get_current_user()
    if user is None:
        return redirect(url_for("emailenter"))
    confirm_text = request.form.get("confirm_text")
    if confirm_text != "delete account":
        return redirect(url_for("dashboard", error='Type "delete account" to confirm'))
    password = request.form.get("password")
    if not password or not auth.verify_user(user["email"], password):
        return redirect(url_for("dashboard", error="Wrong password"))
    auth.delete_user(user["email"])
    logger.info(f"Account deleted: {user['email']}")
    return redirect(url_for("emailenter"))


@app.route("/terms")
def terms():
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <title>Terms of Service - JohnnyID</title>
</head>
<body>
  <main class="container">
    <h1>Terms of Service</h1>
    <p>These Terms of Service ("Terms") govern your use of JohnnyID ("the Service") provided by JohnnyID.</p>

    <h2>1. Acceptance of Terms</h2>
    <p>By accessing and using JohnnyID, you accept and agree to be bound by the terms and provision of this agreement.</p>

    <h2>2. Use License</h2>
    <p>Permission is granted to temporarily access the materials (information or software) on JohnnyID's website for personal, non-commercial transitory viewing only.</p>

    <h2>3. Disclaimer</h2>
    <p>The materials on JohnnyTech's website are provided on an 'as is' basis. JohnnyTech makes no warranties, expressed or implied, and hereby disclaims and negates all other warranties including without limitation, implied warranties or conditions of merchantability, fitness for a particular purpose, or non-infringement of intellectual property or other violation of rights.</p>

    <h2>4. Limitations</h2>
    <p>In no event shall JohnnyTech or its suppliers be liable for any damages (including, without limitation, damages for loss of data or profit, or due to business interruption) arising out of the use or inability to use the materials on JohnnyID's website, even if JohnnyID or a JohnnyID authorized representative has been notified orally or in writing of the possibility of such damage.</p>

    <h2>5. Privacy</h2>
    <p>Your privacy is important to us. Please review our Privacy Policy, which also governs your use of the Service.</p>

    <h2>6. Governing Law</h2>
    <p>These terms and conditions are governed by and construed in accordance with the laws of [Your Jurisdiction], and you irrevocably submit to the exclusive jurisdiction of the courts in that state or location.</p>

    <h2>7. Contact</h2>
    <p>If you have any questions about these Terms, please contact us at [contact email].</p>

    <p>Last updated: Apr 1, 2026</p>
  </main>
</body>
</html>
"""


@app.route("/privacy")
def privacy():
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <title>Privacy Policy - JohnnyID</title>
</head>
<body>
  <main class="container">
    <h1>Privacy Policy</h1>
    <p>This Privacy Policy describes how JohnnyID collects, uses, and protects your information when you use our Service.</p>

    <h2>1. Information We Collect</h2>
    <h3>Personal Information</h3>
    <p>We may collect personally identifiable information such as your name, email address, and authentication credentials when you register for an account or use our Service.</p>

    <h3>Usage Data</h3>
    <p>We may collect information about how you access and use the Service, including IP addresses, browser types, device information, and login history.</p>

    <h2>2. How We Use Your Information</h2>
    <p>We use the information we collect to:</p>
    <ul>
      <li>Provide, maintain, and improve our Service</li>
      <li>Process authentication and authorization</li>
      <li>Send you important updates and notifications</li>
      <li>Monitor and analyze usage patterns</li>
      <li>Prevent fraud and security issues</li>
    </ul>

    <h2>3. Information Sharing</h2>
    <p>We do not sell, trade, or otherwise transfer your personal information to third parties without your consent, except as described in this policy:</p>
    <ul>
      <li>With service providers who assist us in operating our Service</li>
      <li>To comply with legal obligations</li>
      <li>To protect our rights and the rights of others</li>
    </ul>

    <h2>4. Data Security</h2>
    <p>We implement appropriate technical and organizational measures to protect your personal information against unauthorized access, alteration, disclosure, or destruction.</p>

    <h2>5. Data Retention</h2>
    <p>We retain your personal information for as long as necessary to provide our Service and comply with legal obligations.</p>

    <h2>6. Your Rights</h2>
    <p>You have the right to:</p>
    <ul>
      <li>Access your personal information</li>
      <li>Correct inaccurate information</li>
      <li>Delete your account and associated data</li>
      <li>Object to certain processing activities</li>
    </ul>

    <h2>7. Cookies and Tracking</h2>
    <p>We use cookies and similar technologies to enhance your experience and provide our Service. You can manage your cookie preferences through your browser settings.</p>

    <h2>8. Third-Party Services</h2>
    <p>Our Service may integrate with third-party services (such as Google OAuth). Please review the privacy policies of these third parties.</p>

   

    <h2>9. Changes to This Policy</h2>
    <p>We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new policy on this page.</p>

    <h2>10. Contact Us</h2>
    <p>If you have any questions about this Privacy Policy, please contact us at [contact email].</p>

    <p>Last updated: Apr 1, 2026</p>
  </main>
</body>
</html>
"""


@app.errorhandler(403)
def forbidden(e):
    return render_template("error/403.html.j2"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error/404.html.j2"), 404


app.run(debug=True)
