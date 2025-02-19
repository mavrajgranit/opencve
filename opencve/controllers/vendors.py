from flask import abort

from opencve.controllers.base import BaseController
from opencve.models.vendors import Vendor


class VendorController(BaseController):
    model = Vendor
    order = Vendor.name.asc()
    per_page_param = "VENDORS_PER_PAGE"
    schema = {
        "search": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        query = cls.model.query

        # Search by term
        if args.get("search"):
            search = (
                args.get("search")
                .lower()
                .replace("%", "")
                .replace("_", "")
                .replace(" ", "_")
            )
            query = query.filter(cls.model.name.like("%{}%".format(search)))

        return query, {}
