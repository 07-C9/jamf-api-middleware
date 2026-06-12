# ABOUTME: Tests for the EACS Lambda function that proxies EraseDevice commands to Jamf Pro.
# ABOUTME: Covers input validation, Jamf API interactions, and error handling.

import json
import urllib.error

import pytest

from lambda_function import lambda_handler


def _make_event(body_dict):
    return {"body": json.dumps(body_dict)}


def test_valid_erase_request_passes_validation():
    """Validation-only check - verifying the request isn't rejected at validation stage.
    Full Jamf API flow is tested separately in the mocked tests below."""
    from unittest.mock import patch as _patch, MagicMock as _MagicMock
    mock_client = _MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({
            "jamf_url": "https://test.jamfcloud.com",
            "client_id": "fake", "client_secret": "fake",
        })
    }
    token_resp = _MagicMock()
    token_resp.read.return_value = json.dumps({"access_token": "tok"}).encode()
    token_resp.__enter__ = lambda s: s
    token_resp.__exit__ = _MagicMock(return_value=False)
    inv_resp = _MagicMock()
    inv_resp.read.return_value = json.dumps({"totalCount": 0, "results": []}).encode()
    inv_resp.__enter__ = lambda s: s
    inv_resp.__exit__ = _MagicMock(return_value=False)

    with _patch("jamf._get_secrets_client", return_value=mock_client), \
         _patch("jamf.urllib.request.urlopen", side_effect=[token_resp, inv_resp]):
        event = _make_event({
            "serial": "ABCD1234567",
            "udid": "12345678-1234-1234-1234-123456789ABC",
            "action": "erase",
        })
        result = lambda_handler(event, None)
        body = json.loads(result["body"])
        assert body["code"] != "VALIDATION_ERROR"


def test_missing_serial_returns_validation_error():
    event = _make_event({
        "udid": "12345678-1234-1234-1234-123456789ABC",
        "action": "erase",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_missing_udid_returns_validation_error():
    event = _make_event({
        "serial": "ABCD1234567",
        "action": "erase",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_missing_action_returns_validation_error():
    event = _make_event({
        "serial": "ABCD1234567",
        "udid": "12345678-1234-1234-1234-123456789ABC",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_unknown_action_returns_validation_error():
    event = _make_event({
        "serial": "ABCD1234567",
        "udid": "12345678-1234-1234-1234-123456789ABC",
        "action": "delete_everything",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_serial_too_short_returns_validation_error():
    event = _make_event({
        "serial": "ABC",
        "udid": "12345678-1234-1234-1234-123456789ABC",
        "action": "erase",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_serial_with_special_chars_returns_validation_error():
    event = _make_event({
        "serial": "ABCD123; DROP",
        "udid": "12345678-1234-1234-1234-123456789ABC",
        "action": "erase",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_invalid_udid_format_returns_validation_error():
    event = _make_event({
        "serial": "ABCD1234567",
        "udid": "not-a-uuid",
        "action": "erase",
    })
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_empty_body_returns_validation_error():
    event = {"body": "{}"}
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


def test_malformed_json_returns_validation_error():
    event = {"body": "not json at all"}
    result = lambda_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "VALIDATION_ERROR"


from unittest.mock import patch, MagicMock
import os

import jamf

os.environ.setdefault("SECRETS_ARN", "arn:aws:secretsmanager:us-west-2:000000000000:secret:test")


@pytest.fixture(autouse=True)
def _reset_jamf_caches():
    jamf._cached_secrets = None
    jamf._secrets_client = None
    yield
    jamf._cached_secrets = None
    jamf._secrets_client = None


VALID_EVENT = _make_event({
    "serial": "ABCD1234567",
    "udid": "12345678-1234-1234-1234-123456789ABC",
    "action": "erase",
})

FAKE_SECRETS = json.dumps({
    "jamf_url": "https://test.jamfcloud.com",
    "client_id": "fake-id",
    "client_secret": "fake-secret",
})

FAKE_TOKEN_RESPONSE = json.dumps({"access_token": "fake-bearer-token"}).encode()

FAKE_INVENTORY_RESPONSE = json.dumps({
    "totalCount": 1,
    "results": [{
        "id": "42",
        "general": {
            "managementId": "MGMT-UUID-1234-5678-ABCDEF012345",
        },
        "hardware": {
            "serialNumber": "ABCD1234567",
        },
        "security": {
            "bootstrapTokenEscrowedStatus": "ESCROWED",
        },
        "udid": "12345678-1234-1234-1234-123456789ABC",
    }],
}).encode()

FAKE_ERASE_RESPONSE = json.dumps({"id": "cmd-123", "href": "/api/v2/mdm/commands/cmd-123"}).encode()


def _mock_secrets_client():
    client = MagicMock()
    client.get_secret_value.return_value = {"SecretString": FAKE_SECRETS}
    return client


def _make_http_response(data, status=200):
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_happy_path_sends_erase_and_returns_success(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(FAKE_INVENTORY_RESPONSE),
        _make_http_response(FAKE_ERASE_RESPONSE),
    ]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 200
    assert body["code"] == "SUCCESS"

    erase_call = mock_urlopen.call_args_list[2]
    erase_request = erase_call[0][0]
    erase_body = json.loads(erase_request.data)
    assert erase_body["clientData"][0]["managementId"] == "MGMT-UUID-1234-5678-ABCDEF012345"
    assert erase_body["commandData"]["commandType"] == "ERASE_DEVICE"
    assert erase_body["commandData"]["pin"] == "000000"
    assert erase_body["commandData"]["obliterationBehavior"] == "DoNotObliterate"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_device_not_found_returns_error(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    empty_inventory = json.dumps({"totalCount": 0, "results": []}).encode()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(empty_inventory),
    ]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 404
    assert body["code"] == "DEVICE_NOT_FOUND"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_udid_mismatch_returns_error(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    wrong_udid_inventory = json.dumps({
        "totalCount": 1,
        "results": [{
            "id": "42",
            "general": {"managementId": "MGMT-UUID-1234"},
            "hardware": {"serialNumber": "ABCD1234567"},
            "security": {"bootstrapTokenEscrowedStatus": "ESCROWED"},
            "udid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        }],
    }).encode()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(wrong_udid_inventory),
    ]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 403
    assert body["code"] == "UDID_MISMATCH"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_bst_not_escrowed_returns_error(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    no_bst_inventory = json.dumps({
        "totalCount": 1,
        "results": [{
            "id": "42",
            "general": {"managementId": "MGMT-UUID-1234"},
            "hardware": {"serialNumber": "ABCD1234567"},
            "security": {"bootstrapTokenEscrowedStatus": "NOT_ESCROWED"},
            "udid": "12345678-1234-1234-1234-123456789ABC",
        }],
    }).encode()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(no_bst_inventory),
    ]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 400
    assert body["code"] == "BST_NOT_ESCROWED"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_jamf_auth_failure_returns_error(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    error = urllib.error.HTTPError(
        url="https://test.jamfcloud.com/api/oauth/token",
        code=401, msg="Unauthorized", hdrs=None, fp=None,
    )
    mock_urlopen.side_effect = [error]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 500
    assert body["code"] == "JAMF_AUTH_FAILED"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_erase_command_failure_returns_error(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    error_on_erase = urllib.error.HTTPError(
        url="https://test.jamfcloud.com/api/v2/mdm/commands",
        code=500, msg="Internal Server Error", hdrs=None, fp=None,
    )
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(FAKE_INVENTORY_RESPONSE),
        error_on_erase,
    ]

    result = lambda_handler(VALID_EVENT, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 500
    assert body["code"] == "ERASE_FAILED"
