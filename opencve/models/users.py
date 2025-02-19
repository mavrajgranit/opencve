from flask import current_app as app
from flask_user import UserMixin
from sqlalchemy.sql import expression, func
from sqlalchemy_utils import ChoiceType, JSONType

from opencve.constants import FREQUENCIES_TYPES
from opencve.extensions import db
from opencve.models import BaseModel, users_products, users_vendors


def get_default_filters():
    return {
        "cvss": 0,
        "event_types": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }


def get_default_settings():
    return {"activities_view": "all"}


class User(BaseModel, UserMixin):
    __tablename__ = "users"
    __hash__ = UserMixin.__hash__

    # User authentication information
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default="")
    reset_password_token = db.Column(db.String(100), nullable=False, server_default="")

    # User email information
    email = db.Column(db.String(255), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    # Notification parameters
    enable_notifications = db.Column(
        db.Boolean(), nullable=False, server_default=expression.true()
    )
    filters_notifications = db.Column(JSONType, default=get_default_filters)
    settings = db.Column(JSONType, default=get_default_settings, nullable=False)
    frequency_notifications = db.Column(ChoiceType(FREQUENCIES_TYPES), default="always")

    # User information
    active = db.Column(
        "is_active", db.Boolean(), nullable=False, server_default=expression.false()
    )
    first_name = db.Column(db.String(100), nullable=False, server_default="")
    last_name = db.Column(db.String(100), nullable=False, server_default="")
    admin = db.Column(db.Boolean, unique=False, server_default=expression.false())

    # Relationships
    vendors = db.relationship("Vendor", secondary=users_vendors)
    products = db.relationship("Product", secondary=users_products)
    alerts = db.relationship("Alert", back_populates="user")
    reports = db.relationship("Report", back_populates="user")
    tags = db.relationship("UserTag", back_populates="user")
    cve_tags = db.relationship("CveTag", back_populates="user")

    @property
    def is_confirmed(self):
        return bool(self.email_confirmed_at)

    def __repr__(self):
        return "<User {}>".format(self.username)

    def __eq__(self, user):
        return self.id == user.id if user else False

    def set_password(self, password):
        self.password = app.user_manager.hash_password(password)
