# ABOUTME: Tests for the jamf.py Jamf Pro API client module.
# ABOUTME: Covers credential loading, token acquisition, device validation, and MDM command dispatch.

import json
import os
import urllib.error

import pytest

os.environ.setdefault("SECRETS_ARN", "arn:aws:secretsmanager:us-west-2:000000000000:secret:test")

import jamf

from unittest.mock import patch, MagicMock, call

DEVICE_SERIAL = "ABCD1234567"
DEVICE_UDID = "12345678-1234-1234-1234-123456789ABC"
MANAGEMENT_ID = "MGMT-UUID-1234-5678-ABCDEF012345"

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
        "udid": DEVICE_UDID,
        "general": {
            "managementId": MANAGEMENT_ID,
        },
        "hardware": {
            "serialNumber": DEVICE_SERIAL,
        },
        "security": {
            "bootstrapTokenEscrowedStatus": "ESCROWED",
        },
    }],
}).encode()


@pytest.fixture(autouse=True)
def _reset_jamf_caches():
    jamf._cached_secrets = None
    jamf._secrets_client = None
    yield
    jamf._cached_secrets = None
    jamf._secrets_client = None


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
def test_validate_device_returns_context_on_success(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(FAKE_INVENTORY_RESPONSE),
    ]

    ctx, err = jamf.validate_device(DEVICE_SERIAL, DEVICE_UDID)

    assert err is None
    assert ctx is not None
    assert ctx["token"] == "fake-bearer-token"
    assert ctx["jamf_url"] == "https://test.jamfcloud.com"
    assert ctx["device"]["udid"] == DEVICE_UDID


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_validate_device_returns_error_on_auth_failure(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    error = urllib.error.HTTPError(
        url="https://test.jamfcloud.com/api/oauth/token",
        code=401, msg="Unauthorized", hdrs=None, fp=None,
    )
    mock_urlopen.side_effect = [error]

    ctx, err = jamf.validate_device(DEVICE_SERIAL, DEVICE_UDID)

    assert ctx is None
    assert err is not None
    assert err["code"] == "JAMF_AUTH_FAILED"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_validate_device_returns_error_when_not_found(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    empty_inventory = json.dumps({"totalCount": 0, "results": []}).encode()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(empty_inventory),
    ]

    ctx, err = jamf.validate_device(DEVICE_SERIAL, DEVICE_UDID)

    assert ctx is None
    assert err is not None
    assert err["code"] == "DEVICE_NOT_FOUND"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_validate_device_returns_error_on_udid_mismatch(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    wrong_udid_inventory = json.dumps({
        "totalCount": 1,
        "results": [{
            "id": "42",
            "udid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            "general": {"managementId": MANAGEMENT_ID},
            "hardware": {"serialNumber": DEVICE_SERIAL},
            "security": {"bootstrapTokenEscrowedStatus": "ESCROWED"},
        }],
    }).encode()
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        _make_http_response(wrong_udid_inventory),
    ]

    ctx, err = jamf.validate_device(DEVICE_SERIAL, DEVICE_UDID)

    assert ctx is None
    assert err is not None
    assert err["code"] == "UDID_MISMATCH"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_validate_device_returns_error_on_lookup_failure(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    error = urllib.error.HTTPError(
        url="https://test.jamfcloud.com/api/v1/computers-inventory",
        code=500, msg="Internal Server Error", hdrs=None, fp=None,
    )
    mock_urlopen.side_effect = [
        _make_http_response(FAKE_TOKEN_RESPONSE),
        error,
    ]

    ctx, err = jamf.validate_device(DEVICE_SERIAL, DEVICE_UDID)

    assert ctx is None
    assert err is not None
    assert err["code"] == "LOOKUP_FAILED"


@patch("jamf._get_secrets_client")
@patch("jamf.urllib.request.urlopen")
def test_send_mdm_command_posts_correct_payload(mock_urlopen, mock_get_client):
    mock_get_client.return_value = _mock_secrets_client()
    cmd_response = json.dumps({"id": "cmd-999"}).encode()
    mock_urlopen.side_effect = [_make_http_response(cmd_response)]

    command_data = {
        "commandType": "ERASE_DEVICE",
        "pin": "000000",
        "obliterationBehavior": "DoNotObliterate",
    }
    jamf.send_mdm_command(
        "https://test.jamfcloud.com",
        "fake-bearer-token",
        MANAGEMENT_ID,
        command_data,
    )

    assert mock_urlopen.call_count == 1
    request_obj = mock_urlopen.call_args[0][0]
    assert request_obj.get_full_url() == "https://test.jamfcloud.com/api/v2/mdm/commands"
    assert request_obj.get_method() == "POST"
    payload = json.loads(request_obj.data)
    assert payload["clientData"][0]["managementId"] == MANAGEMENT_ID
    assert payload["commandData"]["commandType"] == "ERASE_DEVICE"
    assert payload["commandData"]["pin"] == "000000"
    assert payload["commandData"]["obliterationBehavior"] == "DoNotObliterate"
