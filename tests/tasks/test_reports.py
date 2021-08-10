import json

import pytest
from unittest.mock import patch, Mock, MagicMock
from requests.exceptions import HTTPError
from flask_user import EmailError

from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.vendors import Vendor
from opencve.models.reports import Report
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import (
    get_top_alerts,
    get_sorted_alerts,
    get_users_with_alerts,
    get_vendors_products,
    create_webhook_message,
    handle_reports,
)


def mock_response(status_code=200, content="REPLY", json=None, raise_exception=None):
    """
    Creates a Mock Requests response, which may optionally raise an exception.
    :param status_code: Status code of the response
    :param content: Content/Text to be set for the response
    :param json: Json to be set for the response
    :param raise_exception: Which exception to raise when raise_for_status is called or none
    :return: A Mock of the response object
    """
    mock_response_ = Mock()

    mock_response_.raise_for_status = Mock()
    if raise_exception:
        raise_exception.response = mock_response_
        mock_response_.raise_for_status.side_effect = raise_exception
    mock_response_.status_code = status_code
    mock_response_.content = content

    if json:
        mock_response_.json = Mock(return_value=json)

    return mock_response_


@pytest.mark.parametrize(
    "hour,count",
    [
        ("02:00:00", 1),
        ("10:59:00", 1),
        ("11:00:00", 2),
        ("11:15:00", 2),
        ("11:16:00", 1),
        ("20:00:00", 1),
    ],
)
def test_get_users_with_alerts(freezer, create_user, handle_events, hour, count):
    handle_events("modified_cves/CVE-2018-18074.json")

    # Create 2 users with different frequency notification
    user1 = create_user("user1")
    user1.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user1.frequency_notifications = "always"
    db.session.commit()

    user2 = create_user("user2")
    user2.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user2.frequency_notifications = "once"
    db.session.commit()

    handle_alerts()

    freezer.move_to(f"2021-01-01 {hour}")
    users = get_users_with_alerts()
    assert len(users) == count


def test_get_top_alerts(create_cve, create_user):
    user = create_user()
    db.session.add(Alert(cve=create_cve("CVE-2018-18074"), user=user, details={}))
    db.session.add(Alert(cve=create_cve("CVE-2020-9392"), user=user, details={}))
    db.session.add(Alert(cve=create_cve("CVE-2020-26116"), user=user, details={}))
    db.session.commit()

    # List of alerts is reduced and ordered by CVSS3 desc
    top_alerts = get_top_alerts(user, 1)
    assert [a.cve.cvss3 for a in top_alerts] == [9.8]

    top_alerts = get_top_alerts(user, 3)
    assert sorted([a.cve.cvss3 for a in top_alerts]) == sorted([9.8, 7.3, 7.2])

    top_alerts = get_top_alerts(user, 10)
    assert sorted([a.cve.cvss3 for a in top_alerts]) == sorted([9.8, 7.3, 7.2])


def test_get_sorted_alerts(create_cve, create_user):
    user = create_user()

    # Create an alert with the 'foo' vendor
    alert_26116 = Alert(
        cve=create_cve("CVE-2020-26116"),
        user=user,
        details={"vendors": ["foo"], "products": []},
    )
    db.session.add(alert_26116)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "foo" in sorted_alerts
    assert sorted_alerts["foo"]["name"] == "Foo"
    assert sorted_alerts["foo"]["max"] == 7.2
    assert [a.id for a in sorted_alerts["foo"]["alerts"]] == [alert_26116.id]

    # Add another alert for the same 'foo' vendor but with a higher score
    alert_28074 = Alert(
        cve=create_cve("CVE-2018-18074"),
        user=user,
        details={"vendors": ["foo"], "products": []},
    )
    db.session.add(alert_28074)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "foo" in sorted_alerts
    assert sorted_alerts["foo"]["name"] == "Foo"
    assert sorted_alerts["foo"]["max"] == 9.8
    assert sorted([a.id for a in sorted_alerts["foo"]["alerts"]]) == sorted(
        [alert_26116.id, alert_28074.id]
    )

    # Finally create an alert with the 'bar' product
    alert_9392 = Alert(
        cve=create_cve("CVE-2020-9392"),
        user=user,
        details={"vendors": [], "products": ["bar"]},
    )
    db.session.add(alert_9392)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "bar" in sorted_alerts
    assert sorted_alerts["bar"]["name"] == "Bar"
    assert sorted_alerts["bar"]["max"] == 7.3
    assert [a.id for a in sorted_alerts["bar"]["alerts"]] == [alert_9392.id]


def test_get_vendors_products(create_cve, create_user):
    user = create_user()
    db.session.add(
        Alert(
            cve=create_cve("CVE-2020-26116"),
            user=user,
            details={"vendors": ["foo"], "products": []},
        )
    )
    db.session.add(
        Alert(
            cve=create_cve("CVE-2018-18074"),
            user=user,
            details={"vendors": ["foo"], "products": []},
        )
    )
    db.session.add(
        Alert(
            cve=create_cve("CVE-2020-9392"),
            user=user,
            details={"vendors": [], "products": ["bar"]},
        )
    )
    db.session.commit()

    vendors_products = get_vendors_products(Alert.query.all())
    assert sorted(vendors_products) == sorted(["bar", "foo"])


# Ensures that the Webhook message is properly generated for the "new_csv" type
def test_create_webhook_message_new_csv(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


# Ensures that the Webhook message is properly generated for both the "new_csv" and the "references" type
def test_create_webhook_message_references(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_references.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


# Ensures that the Webhook message is properly generated for both the "new_csv" and the "cpes" type
def test_create_webhook_message_cpes(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_cpes.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


# Ensures that the Webhook message is properly generated for both the "new_csv" and "cvss" type
def test_create_webhook_message_cvss(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_cvss.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


# Ensures that the Webhook message is properly generated for both the "new_csv" and "cwes" type
def test_create_webhook_message_cwes(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_cwes.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


# Ensures that the Webhook message is properly generated for both the "new_csv" and "summary" type
def test_create_webhook_message_summary(create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_summary.json")

    webhook_message, user, report, alerts = pre_webhook(create_user)

    validate_webhook_message(webhook_message, user, report, alerts)
    for alert, alert_summary in zip(alerts, webhook_message["alerts"]):
        compare_alert_to_alert_summary(alert, alert_summary)

        events = alert.events
        for event, event_summary in zip(events, alert_summary["events"]):
            compare_event_to_event_summary(event, event_summary)


def pre_webhook(create_user):
    """
    Creates a User, Report and Webhook message for further use in testing.
    :param create_user: Create User fixture to be used to create the user
    :return: The Webhook message, User, Report and the alerts created during the "handle_alerts" task
    """
    import datetime
    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user.enable_notifications = True
    db.session.commit()

    handle_alerts()

    report = Report(public_link="link",
                    created_at=datetime.datetime(2021, 8, 2, 14, 0, 0),
                    updated_at=datetime.datetime(2021, 8, 3, 14, 0, 0),
                    seen=False,
                    details="[canonical]",
                    user_id=user.id, )
    alerts = Alert.query.filter_by(user_id=user.id).all()
    webhook_message = create_webhook_message(report, alerts, user)

    return webhook_message, user, report, alerts


# validates a given Webhook message
def validate_webhook_message(webhook_message, user, report, alerts):
    assert isinstance(webhook_message, dict)
    assert webhook_message["username"] == user.username
    assert webhook_message["created_at"] == report.created_at.isoformat()
    assert webhook_message["updated_at"] == report.updated_at.isoformat()
    assert webhook_message["public_link"] == report.public_link
    assert webhook_message["vendors_products_summary"] == report.details
    assert webhook_message["alert_count"] == len(alerts)


# compares an alert to a Webhook message's alert summary
def compare_alert_to_alert_summary(alert, alert_summary):
    cve = alert.cve
    events = alert.events

    assert alert_summary["cve"] == cve.cve_id
    assert alert_summary["description"] == cve.summary
    assert alert_summary["details"] == alert.details
    assert alert_summary["created_at"] == alert.created_at.isoformat()
    assert alert_summary["updated_at"] == alert.updated_at.isoformat()
    assert alert_summary["vendors"] == cve.vendors
    assert alert_summary["cwes"] == cve.cwes
    assert alert_summary["cvss2"] == cve.cvss2
    assert alert_summary["cvss3"] == cve.cvss3
    assert alert_summary["event_count"] == len(events)


# compares an event to an alert summary's event summary
def compare_event_to_event_summary(event, event_summary):
    event_details = event.details

    assert event_summary["created_at"] == event.created_at.isoformat()
    assert event_summary["updated_at"] == event.updated_at.isoformat()
    assert event_summary["type"] == event.type.code
    assert event_summary["details"] == event_details
    if event.type == "references":
        assert "added" in event_details
        assert "changed" in event_details
        assert "removed" in event_details


def test_server_name_exceptions(app):
    old = app.config["SERVER_NAME"]
    app.config["SERVER_NAME"] = None

    with pytest.raises(ValueError):
        handle_reports()

    app.config["SERVER_NAME"] = old


@patch("opencve.tasks.reports.webhook.send_message")
@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_without_notification(mock_send, mock_webhook_send, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user.enable_notifications = False
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()

    assert not mock_send.called
    assert not mock_webhook_send.called
    assert Alert.query.filter_by(notify=False).count() == 0


@patch("opencve.tasks.reports.webhook.send_message")
@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_with_notification_webhook_enabled(mock_send, mock_webhook_send, create_user, handle_events, app):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    report = reports[0]
    assert report.user.id == user.id
    assert report.details == ["canonical"]
    assert report.alerts == Alert.query.filter_by(user_id=user.id).all()

    alerts = report.alerts
    assert len(alerts) == 1
    alert = alerts[0]
    cve = alert.cve
    events = alert.events
    assert len(events) == 1
    event = events[0]

    assert mock_send.called
    mock_send.assert_called_with(
        user,
        **{
            "subject": "1 alert on Canonical",
            "total_alerts": 1,
            "alerts_sorted": get_sorted_alerts(Alert.query.all()),
            "report_public_link": Report.query.first().public_link,
        },
    )
    assert mock_webhook_send.called
    mock_webhook_send.assert_called_with(
        app.config["WEBHOOK_URL"],
        {
            'username': user.username,
            'created_at': report.created_at.isoformat(),
            'updated_at': report.updated_at.isoformat(),
            'public_link': report.public_link,
            'vendors_products_summary': report.details,
            'alert_count': len(alerts),
            'alerts': [
                {'cve': cve.cve_id,
                 'description': cve.summary,
                 'details': alert.details,
                 'created_at': alert.created_at.isoformat(),
                 # is updated once alert has been read
                 'updated_at': mock_webhook_send.call_args[0][1]["alerts"][0]["updated_at"],
                 'vendors': cve.vendors,
                 'cwes': cve.cwes,
                 'cvss2': cve.cvss2,
                 'cvss3': cve.cvss3,
                 'event_count': len(events),
                 'events': [{'created_at': event.created_at.isoformat(),
                             'updated_at': event.updated_at.isoformat(),
                             'type': event.type.code,
                             'details': {}}]
                 }
            ]},
        mock_webhook_send.call_args[0][2]
    )
    assert Alert.query.filter_by(notify=False).count() == 0


@patch("opencve.tasks.reports.webhook.send_message")
@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_with_notification_webhook_disabled(mock_send, mock_webhook_send, create_user, handle_events, app):
    old = app.config["GLOBAL_WEBHOOK_ENABLED"]
    app.config["GLOBAL_WEBHOOK_ENABLED"] = False

    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    report = reports[0]
    assert report.user.id == user.id
    assert report.details == ["canonical"]
    assert report.alerts == Alert.query.filter_by(user_id=user.id).all()

    alerts = report.alerts
    assert len(alerts) == 1

    assert mock_send.called
    mock_send.assert_called_with(
        user,
        **{
            "subject": "1 alert on Canonical",
            "total_alerts": 1,
            "alerts_sorted": get_sorted_alerts(Alert.query.all()),
            "report_public_link": Report.query.first().public_link,
        },
    )
    assert not mock_webhook_send.called
    assert Alert.query.filter_by(notify=False).count() == 0

    app.config["GLOBAL_WEBHOOK_ENABLED"] = old


@patch("opencve.tasks.reports.webhook.send_message")
@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_bad_smtp_config(mock_send, mock_webhook_send, create_user, handle_events):
    mock_send.side_effect = EmailError("error")

    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert mock_webhook_send.called
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()
    assert len(reports[0].alerts) == 1
    assert Alert.query.filter_by(notify=False).count() == 0


@patch("requests.post")
@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_webhook_request_exception(mock_send, mock_post, create_user, handle_events):
    mock_post.return_value = mock_response(404, "404 Not Found", raise_exception=HTTPError("404 NOT FOUND"))

    handle_events("modified_cves/CVE-2018-18074.json")
    handle_events("modified_cves/CVE-2018-18074_summary.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    report = reports[0]
    assert report.user.id == user.id
    assert report.details == ["canonical"]
    assert report.alerts == Alert.query.filter_by(user_id=user.id).all()
    assert len(reports[0].alerts) == 1
    assert len(reports[0].alerts[0].events) == 2

    assert mock_send.called
    assert mock_post.called

    assert Alert.query.filter_by(notify=False).count() == 0
