from flask import abort

from opencve.controllers.base import BaseController
from opencve.extensions import db
from opencve.models.integrations import Integration


class IntegrationController(BaseController):
    model = Integration
    order = Integration.created_at.desc()
    per_page_param = "INTEGRATIONS_PER_PAGE"
    schema = {
        "user_id": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        query = Integration.query.filter_by(user_id=args.get("user_id"))
        return query, {}
