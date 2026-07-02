# Jamf API Middleware

Run scripts on managed Macs that trigger Jamf Pro API actions without putting Jamf API credentials on the device.

AWS API Gateway + Lambda + Secrets Manager sit between the fleet and the Jamf Pro API. A device asks the middleware to perform an action on itself. The middleware holds the credentials, verifies the device's identity, and makes the Jamf API call. We run this in production in a K-12 district.

## Problem

A policy script that calls the Jamf Pro API needs credentials. Putting a client ID and secret in the script or its policy parameters means a local admin or malware can recover them, and a Jamf API credential usually has broad reach. Encryption and obfuscation don't change this; the secret still has to be recoverable on the device to be used. See [Stop putting Jamf Pro API credentials on clients](https://macnotes.wordpress.com/2021/11/15/stop-putting-jamf-pro-api-credentials-on-clients/).

The standard answer is middleware. The client authenticates to a service you control with a low-value token. That service holds the real credentials and verifies the request is scoped to the device making it before doing anything.

## Architecture

```
 Mac (no credentials)                AWS                              Jamf Pro
┌─────────────────────┐   ┌──────────────────────────┐   ┌──────────────────────────┐
│ Jamf policy script  │   │ API Gateway (REST)        │   │                          │
│  - reads own serial │──▶│  - API key required       │──▶│                          │
│    + hardware UUID  │   │  - rate limit + quota     │   │                          │
│    via ioreg        │   │  - TLS 1.2 minimum        │   │                          │
│  - POST /<action>   │   │       │                   │   │ 1. OAuth client creds    │
└─────────────────────┘   │       ▼                   │   │ 2. inventory lookup      │
                          │ Lambda (python 3.12)      │   │    by serial             │
                          │  - validate input         │──▶│ 3. UDID cross-check      │
                          │  - serial+UDID must match │   │ 4. action-specific       │
                          │    the same Jamf record   │   │    checks + API call     │
                          │  - dispatch on action     │   │                          │
                          │       │                   │   └──────────────────────────┘
                          │       ▼                   │
                          │ Secrets Manager           │
                          │  (Jamf API client creds)  │
                          └──────────────────────────┘
```

Every request must include the device's serial number and hardware UUID. The Lambda looks the serial up in Jamf and requires the UDID on the matching inventory record to agree before dispatching the action. A device can only act on itself.

## Contents

```
lambda/
  jamf.py              # Jamf Pro API client: OAuth, device lookup by serial,
                       # UDID validation, v2 MDM commands
  lambda_function.py   # input validation, action dispatch, erase action handler
  test_jamf.py         # 6 tests
  test_lambda_function.py  # 16 tests
```

`lambda_function.py` dispatches on an `action` field through an `ACTIONS` dict. One action is included: `erase`, which sends an MDM Erase All Content and Settings command with Bootstrap Token and obliteration-behavior checks. Adding an action is a handler function and a dict entry (see below).

For a production consumer of this middleware, see [jamf-self-service-eacs](https://github.com/07-C9/jamf-self-service-eacs).

## Usage

Any script on a managed device can call the middleware. It needs the gateway URL and an API key, both delivered as Jamf policy parameters. The device reads its own identity locally; no admin rights are needed:

```bash
SERIAL=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $4}')
UDID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $4}')

curl -s -X POST "${GATEWAY_URL}/erase" \
  -H "x-api-key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"erase\",\"serial\":\"${SERIAL}\",\"udid\":\"${UDID}\"}"
```

Responses are JSON with `status`, `code`, and `message`. Error codes are explicit: `DEVICE_NOT_FOUND`, `UDID_MISMATCH`, `BST_NOT_ESCROWED`, `LOOKUP_FAILED`, `JAMF_AUTH_FAILED`, `VALIDATION_ERROR`, `INVALID_DEVICE_RECORD`, `ERASE_FAILED`. Client scripts should read the body's `code` field before falling back to HTTP status. API Gateway itself returns a bodyless 403 (bad key) and 429 (throttled), but a 403 from the Lambda means `UDID_MISMATCH`, which is a different problem than a bad key.

## Security model

- Jamf API credentials exist only in AWS Secrets Manager, readable only by the Lambda execution role.
- A device can only act on itself. Serial and hardware UUID are readable locally without admin rights, but on managed Apple hardware with SIP enabled they cannot be spoofed to impersonate another device. Learning another device's serial and UDID requires Jamf console or API access.
- The API key is throttle and audit, not the security boundary. Assume a local admin can extract it from policy logs or parameters. It only allows asking the middleware to run a scoped action against a device whose serial and UDID you already know, rate limited and logged at every layer (Jamf policy log, API Gateway, CloudWatch). Issue one key per client tool so keys can be revoked independently.
- Least privilege per use case. Each action family gets its own Jamf API role and client with minimum privileges, stored as its own secret. An action with different needs gets a new Jamf API client, not new privileges on an existing one.
- Destructive actions get extra checks. The erase handler refuses devices without an escrowed Bootstrap Token and sends `obliterationBehavior: DoNotObliterate`, so a device that cannot perform EACS fails cleanly instead of obliterating into an OS reinstall.

Trade-off: this is a shared-key-per-tool design, not per-device authentication. For per-device secrets and broader API access, see ChippewaChris's Gustave design (per-device secrets bootstrapped through MDM-delivered configuration profiles, described in MacAdmins Slack #jamf-api). For self-targeting actions validated against device identity, a key plus an identity check is the common pattern.

## Jamf Pro setup

1. Create an API role with the minimum privileges for your action. For the included erase action:
   - `Read Computers`
   - `Send Computer Remote Wipe Command`
   - `View MDM command information in Jamf Pro API` (required but undocumented; the v2 MDM commands endpoint returns 401 without it)
2. Create an API client assigned to that role. Its `client_id`, `client_secret`, and your Jamf URL go in the AWS secret (next section).
3. Write a policy script that follows the usage example above, taking the gateway URL and API key as policy parameters. Don't hardcode either.

## AWS setup

Region and IDs are placeholders. `jamf.py` pins its Secrets Manager client to `us-west-2`; change that to your region.

```bash
# 1. Secret holding the Jamf API client credentials (one secret per Jamf API client)
aws secretsmanager create-secret \
  --name jamf-middleware/erase \
  --description "Jamf Pro API client credentials for the erase action role. Read by the jamf-middleware Lambda." \
  --secret-string '{"jamf_url":"https://jamf.example.com:8443","client_id":"...","client_secret":"..."}'

# 2. Execution role: CloudWatch logs + read that one secret
aws iam create-role --role-name jamf-middleware-lambda-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name jamf-middleware-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name jamf-middleware-lambda-role \
  --policy-name jamf-middleware-secrets-read \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"<SECRET_ARN>"}]}'

# 3. Lambda
cd lambda && zip function.zip lambda_function.py jamf.py
aws lambda create-function --function-name jamf-middleware \
  --runtime python3.12 --handler lambda_function.lambda_handler \
  --role <ROLE_ARN> --zip-file fileb://function.zip \
  --timeout 30 --memory-size 128 \
  --environment 'Variables={SECRETS_ARN=<SECRET_ARN>}' \
  --description "Jamf Pro API middleware for managed Macs. Validates device identity (serial+UDID), executes scoped actions with creds from Secrets Manager."

# 4. REST API: one resource per action, POST with API key required, Lambda proxy integration
aws apigateway create-rest-api --name jamf-middleware-api --endpoint-configuration types=REGIONAL \
  --description "Authenticated REST front end to the jamf-middleware Lambda. Managed Macs send device-scoped Jamf Pro actions so Jamf credentials never live on clients."
# ... create-resource /erase, put-method POST --api-key-required, put-integration AWS_PROXY,
#     lambda add-permission scoped to the method ARN, create-deployment --stage-name prod

# 5. Throttling: usage plan (we run 10 req/s, burst 20, 1000/day) + one API key per client tool

# 6. Raise the TLS floor (API Gateway's default accepts TLS 1.0). Enhanced policies
#    require an endpoint access mode; BASIC means no routing behavior change.
aws apigateway update-rest-api --rest-api-id <API_ID> --patch-operations \
  "op=replace,path=/endpointAccessMode,value=BASIC" \
  "op=replace,path=/securityPolicy,value=SecurityPolicy_TLS13_1_2_2021_06"
```

Write real descriptions on every resource.

## Adding an action

One handler function, one dict entry:

```python
def _handle_yourthing(validated):
    ctx, error = jamf.validate_device(validated["serial"], validated["udid"])
    if error:
        return _response(error["status_code"], error["code"], error["message"])
    # action-specific checks, then jamf.request(...) or jamf.send_mdm_command(...)

ACTIONS = {
    "erase": _handle_erase,
    "yourthing": _handle_yourthing,
}
```

Then add an API Gateway resource for the action, and if its Jamf privileges differ, a new Jamf API role, client, and secret. `jamf.validate_device()` gives every action the same device-identity check.

## Gotchas

1. `View MDM command information in Jamf Pro API` is required to send commands via the v2 MDM endpoint, even though nothing is being viewed. Without it: 401.
2. The `pin` field is required in v2 MDM `commandData` for ERASE_DEVICE, even on Apple Silicon where it is ignored. Without `"pin": "000000"`: Jamf returns 500 `SYSTEM_EXCEPTION`.
3. Use the v2 MDM endpoint, not v1. `POST /api/v1/computer-inventory/{id}/erase` does not support `obliterationBehavior`. `POST /api/v2/mdm/commands` does.
4. Lookup by serial uses RSQL filtering, not a direct endpoint: `GET /api/v1/computers-inventory?filter=hardware.serialNumber=="SERIAL"`. Expect zero or one result and treat anything else as a failure.
5. API Gateway's plain `TLS_1_2` security policy value only works on custom domains. On the API itself, use the enhanced policy names (step 6 above), which also require `endpointAccessMode`.

## Testing

The test suite needs no AWS or Jamf access: `cd lambda && python3 -m pytest` (22 tests).

Against the deployed pipeline, a fake serial like `TEST123456` exercises gateway auth, the secret read, Jamf OAuth, and the inventory lookup, and returns `DEVICE_NOT_FOUND` without touching any real device. Useful as a smoke test after infrastructure changes. Test destructive actions on a device you can afford to lose before scoping any policy wider.

## Prior art and credits

- [Stop putting Jamf Pro API credentials on clients](https://macnotes.wordpress.com/2021/11/15/stop-putting-jamf-pro-api-credentials-on-clients/) - the canonical statement of the problem.
- Gustave by ChippewaChris - a general-purpose Jamf middleware design with per-device secret bootstrapping, shared in MacAdmins Slack #jamf-api and at the PSU MacAdmins conference.
- The MacAdmins Slack #jamf-api community.

## License

MIT.
