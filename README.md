# Jamf API Middleware

Run scripts on managed Macs that trigger Jamf Pro API actions, without putting Jamf API credentials on the device.

This is a small, production-tested implementation of the middleware pattern: AWS API Gateway + Lambda + Secrets Manager sitting between your fleet and the Jamf Pro API. A device asks the middleware to perform an action on itself. The middleware holds the credentials, verifies the device is who it says it is, and makes the Jamf API call. It runs in production on a K-12 fleet of about 10,000 Macs.

## The problem

Sooner or later you want a policy script that calls the Jamf Pro API. Maybe it looks something up, maybe it triggers an MDM command. The tempting shortcut is to put an API client ID and secret in the script or its policy parameters.

Don't. There's no way to put a secret on a client that a local admin or malware can't extract. Encrypt it or obfuscate it all you want, it still ends up on disk or in a process listing in recoverable form, and a Jamf API credential can usually touch the whole fleet. See [Stop putting Jamf Pro API credentials on clients](https://macnotes.wordpress.com/2021/11/15/stop-putting-jamf-pro-api-credentials-on-clients/) for the canonical write-up.

The accepted answer is middleware. The client authenticates to a service you control with a low-value token, and that service, which holds the real credentials, verifies the request is scoped to the device making it before doing anything. This repo is that pattern, kept as small as I could keep it.

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

A device may only act on itself, and the middleware proves it. Every request has to carry the device's serial number and hardware UUID. The Lambda looks the serial up in Jamf and requires the UDID on the matching inventory record to agree before it dispatches the action.

## What ships here

```
lambda/
  jamf.py              # Jamf Pro API client: OAuth, device lookup by serial,
                       # UDID validation, v2 MDM commands
  lambda_function.py   # input validation, action dispatch, erase action handler
  test_jamf.py         # 6 tests
  test_lambda_function.py  # 16 tests
```

The middleware is generic. `lambda_function.py` dispatches on an `action` field through an `ACTIONS` dict, and one action is included as the worked example: `erase`, which sends an MDM Erase All Content and Settings command with Bootstrap Token and obliteration-behavior safety checks. It's the action we run in production. Swap in or add your own.

For a complete production consumer of this middleware (self-service EACS with SwiftDialog confirmations), see [jamf-self-service-eacs](https://github.com/07-C9/jamf-self-service-eacs).

## The client contract

Any script on a managed device can call the middleware. It needs two things, both delivered as Jamf policy parameters: the gateway URL and an API key. The device reads its own identity locally, no admin rights needed:

```bash
SERIAL=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $4}')
UDID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $4}')

curl -s -X POST "${GATEWAY_URL}/erase" \
  -H "x-api-key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"erase\",\"serial\":\"${SERIAL}\",\"udid\":\"${UDID}\"}"
```

Responses are JSON with `status`, `code`, and `message`. Error codes are explicit (`DEVICE_NOT_FOUND`, `UDID_MISMATCH`, `BST_NOT_ESCROWED`, `LOOKUP_FAILED`, `JAMF_AUTH_FAILED`, `VALIDATION_ERROR`, `INVALID_DEVICE_RECORD`, `ERASE_FAILED`), so client scripts can map them to user-facing messages. One thing to get right: read the body's `code` field before falling back to HTTP status. API Gateway itself produces a bodyless 403 (bad key) and 429 (throttled), but a 403 from the Lambda means `UDID_MISMATCH`, which is a different problem than a bad key.

## Security model

Honest version of what protects what:

Jamf API credentials exist only in AWS Secrets Manager, readable only by the Lambda execution role. Nothing on the device can leak what the device never had.

A device can only act on itself. Serial and hardware UUID are both readable locally without admin rights, but on managed Apple hardware with SIP enabled they can't be spoofed to impersonate another device. Learning some other device's serial AND UDID requires Jamf console or API access. An attacker who already has that doesn't need your middleware.

The API key is throttle and audit, not the security boundary. Assume a determined local admin can extract it from policy logs or parameters. All it grants is the ability to ask the middleware to run a scoped action against a device whose serial and UDID you already know, rate limited and logged at every layer (Jamf policy log, API Gateway, CloudWatch). Issue one key per client tool so any key can be revoked without breaking the others.

Least privilege, per use case. Each action family gets its own Jamf API role and client with the minimum privileges, stored as its own secret. The erase client holds exactly three privileges (listed below). A future action with different needs gets a new Jamf API client, not new privileges on this one.

Dangerous actions get extra checks. The erase handler refuses devices without an escrowed Bootstrap Token and sends `obliterationBehavior: DoNotObliterate`, so a device that can't perform a true EACS fails cleanly instead of obliterating itself into an OS reinstall.

The trade-off: this is a shared-key-per-tool design, not per-device authentication. If you need per-device secrets for broader API access, study ChippewaChris's Gustave design (per-device secrets bootstrapped through MDM-delivered configuration profiles, described in MacAdmins Slack #jamf-api). For self-targeting actions validated against device identity, key-plus-identity-check is the community-accepted balance of risk and complexity, and Gustave's author now recommends Lambda over a self-hosted broker anyway.

## Jamf Pro setup

1. Make an API role with the minimum privileges for your action. For the included erase action that's exactly:
   - `Read Computers`
   - `Send Computer Remote Wipe Command`
   - `View MDM command information in Jamf Pro API` - required but undocumented. The v2 MDM commands endpoint returns 401 without it. This is the one that costs people hours.
2. Make an API client assigned to that role. Its `client_id`, `client_secret`, and your Jamf URL go in the AWS secret (next section).
3. Write a policy script that follows the client contract above, taking the gateway URL and API key as policy parameters. Never hardcode either.

## AWS setup

Region and IDs are placeholders, substitute your own. `jamf.py` pins its Secrets Manager client to `us-west-2`, so change that to your region.

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

Write real descriptions on every resource. You will thank yourself in a year.

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

Then add a new API Gateway resource for the action, and if its Jamf privileges differ, a new Jamf API role, client, and secret. `jamf.validate_device()` gives every action the same device-identity guarantee for free.

## Gotchas that cost us real time

1. `View MDM command information in Jamf Pro API` is required to *send* commands via the v2 MDM endpoint, even though you're not viewing anything. Without it: 401.
2. The `pin` field is required in v2 MDM `commandData` for ERASE_DEVICE, even on Apple Silicon where it's ignored. Without `"pin": "000000"`: Jamf returns 500 `SYSTEM_EXCEPTION`.
3. Use the v2 MDM endpoint, not v1. `POST /api/v1/computer-inventory/{id}/erase` doesn't support `obliterationBehavior`. `POST /api/v2/mdm/commands` does.
4. Lookup by serial uses RSQL filtering, not a direct endpoint: `GET /api/v1/computers-inventory?filter=hardware.serialNumber=="SERIAL"`. Expect zero or one result and treat anything else as a failure.
5. API Gateway's plain `TLS_1_2` security policy value only works on custom domains. On the API itself you need the enhanced policy names (step 6 above), which also require `endpointAccessMode`.

## Testing it safely

The test suite needs no AWS or Jamf access: `cd lambda && python3 -m pytest` (22 tests).

For the deployed pipeline, a fake serial like `TEST123456` exercises everything (gateway auth, secret read, Jamf OAuth, inventory lookup) and comes back `DEVICE_NOT_FOUND` without touching any real device. We run it as a smoke test after every infrastructure change. And test destructive actions against a device on your desk before scoping any policy wider.

## Prior art and credits

- [Stop putting Jamf Pro API credentials on clients](https://macnotes.wordpress.com/2021/11/15/stop-putting-jamf-pro-api-credentials-on-clients/) - the canonical statement of the problem.
- Gustave by ChippewaChris - the most thoroughly described general-purpose Jamf middleware design (per-device secret bootstrapping), shared in MacAdmins Slack #jamf-api and at the PSU MacAdmins conference.
- The MacAdmins Slack #jamf-api community, whose middleware discussions shaped the threat model here.

## License

MIT. The included example action permanently destroys data by design. Read every line and test on hardware you can afford to lose before you scope it to anything real.
