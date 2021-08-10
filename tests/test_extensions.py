from unittest.mock import patch, Mock

from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
from opencve.extensions import webhook


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


# Ensures that a successful POST to the Webhook does not raise an exception and returns the response object
@patch("opencve.extensions.requests.post")
def test_webhook_successful_send_message(mock_post, app):
    valid_webhook_message = {"message": "valid"}
    mock_post.return_value = mock_response(200, "")
    response = webhook.send_message(app.config["WEBHOOK_URL"], valid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == valid_webhook_message
    assert response is not None


# Ensures that a HTTP-Error of status 404 is handled properly and returns no response object
@patch("opencve.extensions.requests.post")
def test_webhook_http_error_404_send_message(mock_post, app):
    valid_webhook_message = {"message": "valid"}
    mock_post.return_value = mock_response(404, "404 Not Found", raise_exception=HTTPError("404 NOT FOUND"))

    response = webhook.send_message(app.config["WEBHOOK_URL"], valid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == valid_webhook_message
    assert response is None


# Ensures that a HTTP-Error of status 400 is handled properly and returns no response object
@patch("opencve.extensions.requests.post")
def test_webhook_http_error_400_send_message(mock_post, app):
    invalid_webhook_message = {"missing": "field"}
    mock_post.return_value = mock_response(400, "400 Bad Request. Missing mandatory 'message' field!", raise_exception=HTTPError("400 BAD REQUEST"))

    response = webhook.send_message(app.config["WEBHOOK_URL"], invalid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == invalid_webhook_message
    assert response is None


# Ensures that a Connection-Error is handled properly and returns no response object
@patch("opencve.extensions.requests.post")
def test_webhook_connection_error_send_message(mock_post, app):
    valid_webhook_message = {"message": "valid"}
    mock_post.return_value = mock_response(502, "502 Bad Gateway", raise_exception=ConnectionError("502 BAD GATEWAY"))

    response = webhook.send_message(app.config["WEBHOOK_URL"], valid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == valid_webhook_message
    assert response is None


# Ensures that a Timeout-Error is handled properly and returns no response object
@patch("opencve.extensions.requests.post")
def test_webhook_timeout_error_send_message(mock_post, app):
    valid_webhook_message = {"message": "valid"}
    mock_post.return_value = mock_response(408, "408 Request Timeout", raise_exception=Timeout("508 REQUEST TIMEOUT"))

    response = webhook.send_message(app.config["WEBHOOK_URL"], valid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == valid_webhook_message
    assert response is None


# Ensures that a Request-Error is handled properly and returns no response object
@patch("opencve.extensions.requests.post")
def test_webhook_request_error_send_message(mock_post, app):
    valid_webhook_message = {"message": "valid"}
    mock_post.return_value = mock_response(500, "500 Internal Server Error", raise_exception=RequestException("500 INTERNAL SERVER ERROR"))

    response = webhook.send_message(app.config["WEBHOOK_URL"], valid_webhook_message, app.logger)

    url = mock_post.call_args[0][0]
    message = mock_post.call_args[1]['json']
    assert mock_post.called
    assert url == app.config["WEBHOOK_URL"]
    assert message == valid_webhook_message
    assert response is None
