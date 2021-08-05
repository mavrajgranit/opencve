import importlib

from flask import config, current_app as app
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from opencve.controllers.integrations import IntegrationController
from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.models.cve import Cve
from opencve.models.integrations import Integration
from opencve.models.tags import CveTag, UserTag
from opencve.models.users import get_default_filters
from opencve.extensions import db
from opencve.forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    FiltersNotificationForm,
    IntegrationForm,
    MailNotificationsForm,
    TagForm,
)


def integration_exists(name):
    return Integration.query.filter_by(user_id=current_user.id, name=name).first()


@main.route("/account/subscriptions", methods=["GET"])
@login_required
def subscriptions():
    return render_template("profiles/subscriptions.html")


@main.route("/account/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    mail_notifications_form = MailNotificationsForm(
        obj=current_user,
        enable="yes" if current_user.enable_notifications else "no",
        frequency=current_user.frequency_notifications.code,
    )

    filters = current_user.filters_notifications or {"event_types": [], "cvss": 0}
    filters_notifications_form = FiltersNotificationForm(
        obj=current_user,
        new_cve=True if "new_cve" in filters["event_types"] else False,
        references=True if "references" in filters["event_types"] else False,
        cvss=True if "cvss" in filters["event_types"] else False,
        cpes=True if "cpes" in filters["event_types"] else False,
        summary=True if "summary" in filters["event_types"] else False,
        cwes=True if "cwes" in filters["event_types"] else False,
        cvss_score=filters["cvss"],
    )

    if request.method == "POST":
        form_name = request.form["form-name"]

        if (
            form_name == "mail_notifications_form"
            and mail_notifications_form.validate()
        ):
            current_user.enable_notifications = (
                True if mail_notifications_form.enable.data == "yes" else False
            )
            current_user.frequency_notifications = (
                mail_notifications_form.frequency.data
            )
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
            return redirect(url_for("main.notifications"))

        if (
            form_name == "filters_notifications_form"
            and filters_notifications_form.validate()
        ):
            filters = {
                "event_types": [],
                "cvss": filters_notifications_form.cvss_score.data,
            }

            for typ in ["new_cve", "references", "cvss", "cpes", "cwes", "summary"]:
                if getattr(filters_notifications_form, typ).data:
                    filters["event_types"].append(typ)

            current_user.filters_notifications = filters
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
            return redirect(url_for("main.notifications"))

    return render_template(
        "profiles/notifications.html",
        mail_notifications_form=mail_notifications_form,
        filters_notifications_form=filters_notifications_form,
    )


@main.route("/account/tags", methods=["GET", "POST"])
@login_required
def tags():
    tags, _, pagination = UserTagController.list(
        {**request.args, "user_id": current_user.id}
    )
    tag_form = TagForm()

    # Form has been submitted
    if request.method == "POST" and tag_form.validate():

        # Check if the tag doesn't already exist
        if UserTag.query.filter_by(
            user_id=current_user.id, name=tag_form.name.data
        ).first():
            flash("This tag already exists.", "error")

        # Create the new tag
        else:
            tag = UserTag(
                user=current_user,
                name=tag_form.name.data,
                description=tag_form.description.data,
                color=tag_form.color.data,
            )
            db.session.add(tag)
            db.session.commit()

            flash(f"The tag {tag.name} has been successfully added.", "success")
            return redirect(
                url_for("main.edit_tag", tag=tag.name, page=request.args.get("page"))
            )

    return render_template(
        "profiles/tags.html",
        tags=tags,
        form=tag_form,
        pagination=pagination,
        mode="create",
    )


@main.route("/account/tags/<string:tag>", methods=["GET", "POST"])
@login_required
def edit_tag(tag):
    tag = UserTagController.get({"user_id": current_user.id, "name": tag})
    if not tag:
        return redirect(url_for("main.tags"))

    tag_form = TagForm(obj=tag, color=tag.color)

    if request.method == "POST" and tag_form.validate():

        # Prohibit name change
        if tag_form.name.data != tag.name:
            return redirect(url_for("main.tags"))

        # Update the tag
        tag_form.populate_obj(tag)
        tag.color = tag_form.color.data
        db.session.commit()

        flash(f"The tag {tag.name} has been successfully updated.", "success")
        return redirect(
            url_for("main.edit_tag", tag=tag.name, page=request.args.get("page"))
        )

    tags, _, pagination = UserTagController.list(
        {**request.args, "user_id": current_user.id}
    )

    return render_template(
        "profiles/tags.html",
        tags=tags,
        form=tag_form,
        pagination=pagination,
        mode="update",
    )


@main.route("/account/tags/<string:tag>/delete", methods=["GET", "POST"])
@login_required
def delete_tag(tag):
    tag = UserTagController.get({"user_id": current_user.id, "name": tag})
    if not tag:
        return redirect(url_for("main.tags"))

    count = (
        db.session.query(Cve.id)
        .join(CveTag)
        .filter(CveTag.user_id == current_user.id)
        .filter(CveTag.tags.contains([tag.name]))
        .count()
    )

    if count > 0:
        flash(
            f"The tag {tag.name} is still associated to {count} CVE(s), detach them before removing the tag.",
            "error",
        )
        return redirect(url_for("main.tags"))

    # Confirmation page
    if request.method == "GET":
        return render_template("profiles/delete_tag.html", tag=tag, count=count)

    # Delete the tag
    else:
        db.session.delete(tag)
        db.session.commit()
        flash(f"The tag {tag.name} has been deleted.", "success")
        return redirect(url_for("main.tags"))


@main.route("/account/integrations", methods=["GET"])
@login_required
def integrations():
    integrations, _, pagination = IntegrationController.list(
        {**request.args, "user_id": current_user.id}
    )
    return render_template("profiles/integrations.html", integrations=integrations)


@main.route("/account/integrations/add", methods=["GET", "POST"])
@login_required
def add_integration():
    type = request.args.get("type")
    if type not in ["email", "webhook", "slack"]:
        return redirect(url_for("main.integrations"))

    integation_cls = getattr(
        importlib.import_module("opencve.forms"), f"{type.capitalize()}Integration"
    )
    form = integation_cls(type=type)

    if request.method == "POST" and form.validate():

        if integration_exists(form.name.data):
            flash(f"An integration named '{form.name.data}' already exists.", "error")
            return render_template(
                "profiles/integration.html", form=form, type=type, mode="create"
            )

        # Extract the custom fields and populate the configuration data
        custom_fields = [
            k for k in integation_cls.__dict__.keys() if not k.startswith("_")
        ]
        configuration = {field: getattr(form, field).data for field in custom_fields}

        # Extract alert filters
        filters = {
            "event_types": [],
            "cvss": form.alert_filters.cvss_score.data,
        }

        for typ in ["new_cve", "references", "cvss", "cpes", "cwes", "summary"]:
            if getattr(form.alert_filters, typ).data:
                filters["event_types"].append(typ)

        integration = Integration(
            user=current_user,
            name=form.name.data,
            type=type,
            enabled=form.enabled.data,
            report=form.report.data,
            alert_filters=filters,
            configuration=configuration,
        )
        db.session.add(integration)
        db.session.commit()

        flash(
            f"The integration '{integration.name}' has been successfully added.",
            "success",
        )
        return redirect(url_for("main.integrations", page=request.args.get("page")))
    else:
        return render_template(
            "profiles/integration.html", form=form, type=type, mode="create"
        )


@main.route("/account/integrations/<string:name>", methods=["GET", "POST"])
@login_required
def edit_integration(name):
    integration = IntegrationController.get({"user_id": current_user.id, "name": name})

    # Populate the custom fields
    if integration.configuration:
        for key in integration.configuration.keys():
            setattr(integration, key, integration.configuration.get(key))

    integation_cls = getattr(
        importlib.import_module("opencve.forms"),
        f"{integration.type.capitalize()}Integration",
    )

    # Populate alert filters
    event_types = integration.alert_filters["event_types"]
    integration.alert_filters["cvss_score"] = integration.alert_filters.pop("cvss")

    for typ in get_default_filters().get("event_types"):
        integration.alert_filters[typ] = True if typ in event_types else False

    form = integation_cls(obj=integration)

    if request.method == "POST" and form.validate():

        # Check if new name doesn't already exist
        if form.name.data != integration.name:
            if integration_exists(form.name.data):
                flash(
                    f"An integration named '{form.name.data}' already exists.", "error"
                )
                return render_template(
                    "profiles/integration.html",
                    form=form,
                    type=integration.type,
                    mode="update",
                )

        # Extract the custom fields and populate the configuration data
        custom_fields = [
            k for k in integation_cls.__dict__.keys() if not k.startswith("_")
        ]
        configuration = {field: getattr(form, field).data for field in custom_fields}

        # Extract alert filters
        filters = {
            "event_types": [],
            "cvss": form.alert_filters.cvss_score.data,
        }

        for typ in get_default_filters().get("event_types"):
            if getattr(form.alert_filters, typ).data:
                filters["event_types"].append(typ)

        integration.name = form.name.data
        integration.enabled = form.enabled.data
        integration.report = form.report.data
        integration.configuration = configuration
        integration.alert_filters = filters
        db.session.commit()

        flash(
            f"The integration {integration.name} has been successfully updated.",
            "success",
        )
        return redirect(url_for("main.edit_integration", name=integration.name))

    return render_template(
        "profiles/integration.html",
        form=form,
        type=integration.type,
        mode="update",
    )


@main.route("/account/integrations/<string:name>/delete", methods=["GET", "POST"])
@login_required
def delete_integration(name):
    integration = IntegrationController.get({"user_id": current_user.id, "name": name})

    # Confirmation page
    if request.method == "GET":
        return render_template(
            "profiles/delete_integration.html", integration=integration
        )

    # Delete the tag
    else:
        db.session.delete(integration)
        db.session.commit()
        flash(f"The integration '{integration.name}' has been deleted.", "success")
        return redirect(url_for("main.integrations"))
