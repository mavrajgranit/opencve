from celery import Celery
from flask_admin import Admin
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import current_user
from flask_gravatar import Gravatar
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, EmailManager
from flask_user.forms import EditUserProfileForm, RegisterForm, unique_email_validator
from flask_wtf import RecaptchaField
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
import requests
from wtforms import validators, StringField


class CustomUserManager(UserManager):
    """
    Add custom properties in default Flask-User objects.
    """

    def customize(self, app):
        def _unique_email_validator(form, field):
            """
            Check if the new email is unique. Skip this step if the
            email is the same as the current one.
            """
            if field.data.lower() == current_user.email.lower():
                return
            unique_email_validator(form, field)

        # Add the email field and make first and last names as not required
        class CustomUserProfileForm(EditUserProfileForm):
            first_name = StringField("First name")
            last_name = StringField("Last name")
            email = StringField(
                "Email",
                validators=[
                    validators.DataRequired(),
                    validators.Email(),
                    _unique_email_validator,
                ],
            )

        self.EditUserProfileFormClass = CustomUserProfileForm

        # Add the reCaptcha
        if app.config.get("DISPLAY_RECAPTCHA"):

            class CustomRegisterForm(RegisterForm):
                recaptcha = RecaptchaField()

            self.RegisterFormClass = CustomRegisterForm

        # Allow emails to be send using sendmail
        if app.config.get("EMAIL_ADAPTER") == "sendmail":
            from flask_user.email_adapters import SendmailEmailAdapter

            self.email_adapter = SendmailEmailAdapter(app)


class CustomEmailManager(EmailManager):
    def send_user_report(self, user, **kwargs):
        """Send the 'user report' email."""
        self._render_and_send_email(
            user.email,
            user,
            "emails/report",
            **kwargs,
        )


class FlaskCelery(Celery):
    """
    Provide the init_app function.
    """

    def __init__(self, *args, **kwargs):
        super(FlaskCelery, self).__init__(*args, **kwargs)

        if "app" in kwargs:
            self.init_app(kwargs["app"])

    def init_app(self, app):
        self.app = app
        self.conf.update(app.config.get("CELERY_CONF", {}))


class Webhook:
    """
    A Webhook class which is used to send a Webhook message to a specified url and handle and log errors.
    """

    def send_message(self, url, message, logger):
        """
        Sends a (JSON) dict message to the specified URL and raises an error in case the response status code is not 2xx
        Exceptions are handled and logged.
        :param url: Url where to send the message to
        :param message: Message to be sent. Needs to be JSON serializable
        :param logger: Logger to be used for logging errors
        :return: The request response or None if an exception was raised
        """
        try:
            response = requests.post(url, json=message)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as http_error:
            error_response = http_error.response
            logger.error("POST request to '{}' failed due to '{}'. Error message: '{}'".format(url, error_response.text, str(http_error)))
        except requests.exceptions.ConnectionError as connection_error:
            logger.error("Unable to connect to '{}'! Error message: '{}'".format(url, str(connection_error)))
        except requests.exceptions.Timeout as timeout_error:
            logger.error("Connection to '{}' timed out! Error message: '{}':".format(url, str(timeout_error)))
        except requests.exceptions.RequestException as request_exception:
            logger.error("An unexpected error occurred while issuing a POST request to '{}'! Error message: '{}'".format(url, str(request_exception)))


# Debug toolbar
debug_toolbar = DebugToolbarExtension()

# CSRF protection
csrf = CSRFProtect()

# SQLAlchemy
db = SQLAlchemy(session_options={"autoflush": False})

# Flask gravatar
gravatar = Gravatar(
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    use_ssl=True,
    base_url=None,
)

# Flask migrate
migrate = Migrate()

# Flask-User
user_manager = CustomUserManager(None, None, None)

# Celery
cel = FlaskCelery("opencve", include=["opencve.tasks"])

# Flask Limiter
limiter = Limiter(key_func=lambda: "Remove the default warning")

# Webhook
webhook = Webhook()
