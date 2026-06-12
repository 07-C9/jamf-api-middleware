# ABOUTME: AWS Lambda middleware handler that receives action requests and dispatches them.
# ABOUTME: Validates inputs, delegates Jamf API calls to the jamf module, and returns API Gateway responses.

import json
import logging
import re
import urllib.error

import jamf

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9]{8,14}$")
UUID_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)


def _response(status_code, code, message):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "status": "error" if status_code >= 400 else "success",
            "code": code,
            "message": message,
        }),
    }


def _validate_request(body):
    serial = body.get("serial", "")
    udid = body.get("udid", "")
    action = body.get("action", "")

    if not serial or not udid or not action:
        return None, "Missing required fields: serial, udid, action"

    if action not in ACTIONS:
        return None, f"Unknown action: {action}"

    if not SERIAL_PATTERN.match(serial):
        return None, "Invalid serial number format"

    if not UUID_PATTERN.match(udid):
        return None, "Invalid UDID format"

    return {"serial": serial, "udid": udid, "action": action}, None


def _handle_erase(validated):
    serial = validated["serial"]
    udid = validated["udid"]

    ctx, error = jamf.validate_device(serial, udid)
    if error:
        return _response(error["status_code"], error["code"], error["message"])

    device = ctx["device"]
    management_id = device.get("general", {}).get("managementId", "")
    bst_status = device.get("security", {}).get("bootstrapTokenEscrowedStatus", "")

    if not management_id:
        logger.error("Missing managementId for serial=%s", serial)
        return _response(500, "INVALID_DEVICE_RECORD", "Device record missing management ID")

    if bst_status != "ESCROWED":
        logger.warning("BST not escrowed: status=%s serial=%s", bst_status, serial)
        return _response(400, "BST_NOT_ESCROWED",
                         "Bootstrap Token not escrowed - cannot perform safe EACS")

    try:
        jamf.send_mdm_command(ctx["jamf_url"], ctx["token"], management_id, {
            "commandType": "ERASE_DEVICE",
            "pin": "000000",
            "obliterationBehavior": "DoNotObliterate",
        })
    except urllib.error.HTTPError as e:
        logger.error("Erase command failed: %d %s serial=%s", e.code, e.reason, serial)
        return _response(500, "ERASE_FAILED", "Failed to send erase command to Jamf Pro")

    logger.info("Erase command sent: serial=%s management_id=%s", serial, management_id)
    return _response(200, "SUCCESS", "Erase command sent successfully")


# ACTIONS must be defined after handler functions so Python can resolve the references.
ACTIONS = {
    "erase": _handle_erase,
}


def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body", "{}"))
    except (json.JSONDecodeError, TypeError):
        return _response(400, "VALIDATION_ERROR", "Invalid JSON body")

    validated, error = _validate_request(body)
    if error:
        logger.info("Validation failed: %s", error)
        return _response(400, "VALIDATION_ERROR", error)

    return ACTIONS[validated["action"]](validated)
