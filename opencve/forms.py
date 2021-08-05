from flask import current_app as app
from sqlalchemy.sql.sqltypes import INT, String
from flask_login import current_user
from flask_user.forms import unique_email_validator
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    SubmitField,
    FieldList,
    FormField,
    validators,
    ValidationError,
)

from opencve.constants import CVSS_SCORES, FREQUENCIES_TYPES, INTEGRATIONS_TYPES
from opencve.models.integrations import Integration


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    new_password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    submit = SubmitField("Change password")

    def validate(self):
        user_manager = app.user_manager

        if not super(ChangeEmailForm, self).validate():
            return False

        if not current_user or not user_manager.verify_password(
            self.password.data, current_user
        ):
            self.password.errors.append("Password is incorrect")
            return False

        return True


class ChangeEmailForm(FlaskForm):
    email = StringField(
        "New email",
        validators=[
            validators.DataRequired("Email is required"),
            validators.Email("Invalid email"),
            unique_email_validator,
        ],
    )
    password = PasswordField(
        "Password", validators=[validators.DataRequired("Password is required")]
    )
    submit = SubmitField("Change email")

    def validate(self):
        user_manager = app.user_manager

        if not super(ChangeEmailForm, self).validate():
            return False

        if not current_user or not user_manager.verify_password(
            self.password.data, current_user
        ):
            self.password.errors.append("Password is incorrect")
            return False

        return True


class MailNotificationsForm(FlaskForm):
    enable = RadioField(
        "Enable email notifications", choices=[("yes", "Yes"), ("no", "No")]
    )
    frequency = SelectField("Email frequency", choices=FREQUENCIES_TYPES)
    submit = SubmitField("Save changes")


class FiltersNotificationForm(FlaskForm):
    new_cve = BooleanField("New CVE")
    references = BooleanField("Reference changed")
    cvss = BooleanField("CVSS changed")
    cpes = BooleanField("CPE changed")
    summary = BooleanField("Summary changed")
    cwes = BooleanField("CWE changed")
    cvss_score = SelectField("CVSS score", coerce=int, choices=CVSS_SCORES)
    submit = SubmitField("Save changes")


class TagForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            validators.DataRequired("Name is required"),
            validators.Regexp(
                "^[a-zA-Z0-9\-_]+$",
                message="Only alphanumeric, dash and underscore characters are accepted",
            ),
        ],
    )
    description = StringField("Description")
    color = StringField(
        "Color",
        validators=[
            validators.DataRequired("Color is required"),
            validators.Regexp(
                "^#[0-9a-fA-F]{6}$", message="Color must be in hexadecimal format"
            ),
        ],
        default="#000000",
    )
    submit = SubmitField("Save")


class IntegrationForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            validators.DataRequired("Name is required"),
            validators.Regexp(
                "^[a-zA-Z0-9\-_ ]+$",
                message="Only alphanumeric, dash, underscore characters and spaces are accepted",
            ),
        ],
    )
    type = SelectField("Type", choices=INTEGRATIONS_TYPES)
    enabled = BooleanField("Enabled", default=True)
    report = BooleanField("Report")
    alert_filters = FormField(FiltersNotificationForm)
    submit = SubmitField("Save")


class KeyValueForm(FlaskForm):
    class Meta:
        csrf = False

    name = StringField(validators=[validators.DataRequired("Name is required")])
    value = StringField(validators=[validators.DataRequired("Value is required")])


class EmailIntegration(IntegrationForm):
    pass


class WebhookIntegration(IntegrationForm):
    url = StringField(
        "Url",
        validators=[
            validators.DataRequired("Url is required"),
        ],
    )
    headers = FieldList(FormField(KeyValueForm))


class SlackIntegration(IntegrationForm):
    url = StringField(
        "Url",
        validators=[
            validators.DataRequired("Url is required"),
        ],
    )
