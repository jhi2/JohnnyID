import sentry_sdk  # type: ignore
from flask import *  # type: ignore
from jjwrapper import *  # type: ignore
import logging
import json
import requests as rq
from tinydb import TinyDB, Query  # type: ignore
from turnstile import *  # type: ignore
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
cpenv = create_jinja_env(template_dir="components")
lb = TinyDB("logininfo.json")
Device = Query()


def lookup_user_agents(ip):
    return [doc["user_agent"] for doc in lb.search(Device.ip == ip)]


def lookup_ips(user_agent):
    return [doc["ip"] for doc in lb.search(Device.user_agent == user_agent)]


@app.route("/")
def root():
    return redirect(url_for("emailenter"))


@app.route("/l/email/")
def emailenter():
    return render_template(
        "lgbase.html.j2",
        stage="Enter your email address to continue.",
        formhtml=render_component(
            cpenv, "email_field.html.j2", security_device_verify=url_for("trackdevice"),callbackuri=url_for("passwordenter")
        ),
    )


@app.route("/internal/trackdevice/", methods=["POST"])
def trackdevice():
    body = request.json
    logger.info(f"User agent: {body['user_agent']}")
    logger.info(f"IP address: {body['ip']}")

    useragents = lookup_user_agents(body["ip"])
    newua = False
    newip = False
    if body["user_agent"] not in useragents:
        logger.warning(
            f"New device detected for IP {body['ip']}: {body['user_agent']} Is the user on a new device or browser?"
        )
        # Notify user of unrecognized device
        newua = True
    ips = lookup_ips(body["user_agent"])
    if body["ip"] not in ips:
        logger.warning(
            f"New IP detected for user agent {body['user_agent']}: {body['ip']} Is the user on a new network?"
        )
        # Notify user of unrecognized location
        newip = True
    lb.insert(body)
    return jsonify({"status": "userrecorded"})

@app.route("/l/pwd/",methods=["POST"])
def passwordenter():
    if request.method == "POST":
        return render_template(
            "lgbase.html.j2",
            stage="Enter your password to continue.",
            formhtml=render_component(
                cpenv, "password_field.html.j2",callbackuri=url_for("root")
            ),
        )
    else:
        return abort(403)

@app.errorhandler(403)
def forbidden(e):
    return render_template("error/403.html.j2"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error/404.html.j2"), 404


app.run(debug=True)
