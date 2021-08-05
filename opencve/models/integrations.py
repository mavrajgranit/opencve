from sqlalchemy.schema import UniqueConstraint
from sqlalchemy_utils import JSONType, UUIDType

from opencve.extensions import db
from opencve.models import BaseModel
from opencve.models.users import get_default_filters


class Integration(BaseModel):
    __tablename__ = "integrations"

    name = db.Column(db.String(), nullable=False)
    type = db.Column(db.String(), nullable=False)
    configuration = db.Column(JSONType(), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    report = db.Column(db.Boolean, default=False)
    alert_filters = db.Column(JSONType, default=get_default_filters)

    # Relationships
    user_id = db.Column(UUIDType(binary=False), db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="integrations")

    __table_args__ = (
        UniqueConstraint("name", "user_id", name="ix_integration_name_userid"),
    )

    def __repr__(self):
        return "<Integration {}>".format(self.name)
