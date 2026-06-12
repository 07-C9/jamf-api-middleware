# ABOUTME: Jamf Pro API client for authenticating, looking up devices, and sending MDM commands.
# ABOUTME: Used by Lambda action handlers to share credential loading, token acquisition, and device validation logic.

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_secrets_client = None
_cached_secrets = None


def _get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        import boto3
        _secrets_client = boto3.client("secretsmanager", region_name="us-west-2")
    return _secrets_client


def _get_credentials():
    global _cached_secrets
    if _cached_secrets is not None:
        return _cached_secrets
    client = _get_secrets_client()
    secret_arn = os.environ["SECRETS_ARN"]
    resp = client.get_secret_value(SecretId=secret_arn)
    _cached_secrets = json.loads(resp["SecretString"])
    return _cached_secrets


def _get_token(jamf_url, client_id, client_secret):
    token_url = f"{jamf_url}/api/oauth/token"
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(token_url, data=body)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["access_token"]


def request(url, token, data=None, method="GET"):
    """Raises urllib.error.HTTPError on HTTP errors, json.JSONDecodeError on malformed responses."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _lookup_device(jamf_url, token, serial):
    encoded_filter = urllib.parse.quote(f'hardware.serialNumber=="{serial}"')
    url = (
        f"{jamf_url}/api/v1/computers-inventory"
        f"?section=GENERAL&section=SECURITY"
        f"&filter={encoded_filter}"
    )
    return request(url, token)


def validate_device(serial, udid):
    """Authenticate with Jamf, look up the device by serial, and verify the UDID matches.

    Returns (context_dict, None) on success where context_dict contains:
      - token: the Jamf bearer token
      - jamf_url: the Jamf Pro base URL
      - device: the device record from computers-inventory

    Returns (None, error_dict) on failure where error_dict contains:
      - status_code, code, message
    """
    creds = _get_credentials()
    jamf_url = creds["jamf_url"]

    try:
        token = _get_token(jamf_url, creds["client_id"], creds["client_secret"])
    except urllib.error.HTTPError as e:
        logger.error("Jamf auth failed: %d %s", e.code, e.reason)
        return None, {"status_code": 500, "code": "JAMF_AUTH_FAILED",
                      "message": "Failed to authenticate with Jamf Pro"}

    try:
        inventory = _lookup_device(jamf_url, token, serial)
    except urllib.error.HTTPError as e:
        logger.error("Device lookup failed: %d %s", e.code, e.reason)
        return None, {"status_code": 500, "code": "LOOKUP_FAILED",
                      "message": "Failed to query Jamf inventory"}

    if inventory.get("totalCount", 0) == 0:
        logger.info("Device not found: serial=%s", serial)
        return None, {"status_code": 404, "code": "DEVICE_NOT_FOUND",
                      "message": "Device not found in Jamf inventory"}

    device = inventory["results"][0]
    device_udid = device.get("udid", "")

    if device_udid.upper() != udid.upper():
        logger.warning("UDID mismatch: expected=%s got=%s serial=%s", udid, device_udid, serial)
        return None, {"status_code": 403, "code": "UDID_MISMATCH",
                      "message": "Device identity verification failed"}

    return {"token": token, "jamf_url": jamf_url, "device": device}, None


def send_mdm_command(jamf_url, token, management_id, command_data):
    """Send an MDM command to a device via the v2 MDM commands endpoint."""
    url = f"{jamf_url}/api/v2/mdm/commands"
    payload = {
        "clientData": [{"managementId": management_id}],
        "commandData": command_data,
    }
    return request(url, token, data=payload, method="POST")
