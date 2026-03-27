import sentry_sdk # type: ignore
from flask import * # type: ignore
from jjwrapper import * # type: ignore
import logging
sentry_sdk.init(
    dsn="https://7826562e2ee5c1f03edfefa0c4caf4cf@o4510961581162496.ingest.de.sentry.io/4511114260054096",
    send_default_pii=True,
    traces_sample_rate=1.0,
    profile_session_sample_rate=1.0,
    profile_lifecycle="trace",
    enable_logs=True
)

logger = logging.getLogger(__name__)
app = Flask(__name__)


@app.route("/")
def root():
    logger.info("Hello there!")
    return render_template("lgbase.html",stage="Hello there!")


if __name__ == "__main__":
    app.run(debug=True)