import sentry_sdk # type: ignore
from flask import * # type: ignore
from jjwrapper import * # type: ignore
sentry_sdk.init(
    dsn="https://7826562e2ee5c1f03edfefa0c4caf4cf@o4510961581162496.ingest.de.sentry.io/4511114260054096",
    send_default_pii=True,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("lgbase.html")


if __name__ == "__main__":
    app.run()