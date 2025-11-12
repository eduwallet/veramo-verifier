# Veramo Verifier

The Veramo-Verifier is a Veramo based agent that assists in handling the OpenID4VCP presentation protocol flow.

## Environment variables

Secrets and connection parameters can be configured using the `.env` specification:

```text
DB_NAME=<postgres database name, default postgres>
DB_SCHEMA=<postgres database schema name, default verifier>
DB_USER=<postgres database user name, default postgres>
DB_PASSWORD=<postgres database password, default postgres>
DB_HOST=<postgres database host, default localhost>
DB_PORT=<postgres database port, default 5432>

PORT=<port number for the verifier agent to listen to, default 5000>
LISTEN_ADDRESS=<network interface address to bind to, default 0.0.0.0>
BASEURL=<base Url for the verifier agent, default https://verifier.dev.eduwallet.nl>
BEARER_TOKEN=<token used for the generic administrative interface>
PASSPHRASE=<token used for encryption of private keys in the database>
```

## Installation

Run `yarn` to install the basic packages:

`yarn install`

## Configuration

Configuration falls into three categories:

- dids
- presentations
- verifiers

### DIDs

The dids are configured in the `conf/dids` path and describe how to create the key if it does not yet exist in the database. Each key has an alias that can be referenced in the `instance` specification.

An example configuration looks like:

```json
{
    "alias": "did:jwk:secp256r1",
    "provider": "did:jwk",
    "type": "Secp256r1"
}
```

This defines a `did:jwk` key (`provider`) of type `secp256r1` (aka `p-256`) and supplies an alias that can be used elsewhere.

### Presentations

The verifiable presentations are JSON documents in the `conf/presentations` path, describing the request for a specific credential. The presentations can either contain a PEX request, according to the https://identity.foundation/presentation-exchange/spec/v2.0.0/ specification on Presentation Exchange. Or they contain a `dcql` query.

Each such presentation is defined by the `id` attribute in the document.

An example looks like:

```json
{
    "id": "ABC",
    "name": "ABC Proeftuin Credential",
    "purpose": "Proeftuin requires the credential content",
    "input_descriptors": [{
        "id": "ABC",
        "name": "ABC Proeftuin Credential",
        "purpose": "Proeftuin requires the credential content",
        "schema": [{
            "uri": "AcademicBaseCredential"
        }],
        "constraints": {
            "fields": [{
                "path": ["$.credentialSubject.id"]
            }]
        }
    }]
}
```

This defines a PEX presentation by using the `input_descriptors` attribute. The presentation is named `ABC` and it requests a credential of type `AcademicBaseCredential` (`input_descriptors.schema.uri`). It requests the `credentialSubject.id` field, but because this is a `jwt_vc_json` type of credential, the wallet will return the complete and fully disclosed credential.

An example using `dcql`:

```json
{
    "id": "GC",
    "name": "Generic Proeftuin Credential",
    "purpose": "Proeftuin requires the credential content",
    "query": {
      "credentials": [{
        "id": "GC",
        "format": "jwt_vc_json",
        "claims": [{
          "path": ["credentialSubject", "id"]
        }]
      }]
    }
}
```

This example uses the `query` attribute to specify the `dcql` query for the presentation. This query is integrated in the authorization request and not available as a separate presentation. The query requests a credential of format `jwt_vc_json` with an attribute `credentialSubject.id`. 

### Verifiers

The `conf/verifiers` are a set of endpoints that are callable by front-end-verifiers and wallets. For each `instance` the configuration specifies the `subpath`, the administrator bearer `token`, the `did` used for this `instance` and the Verifiable Presentations that are allowed (by id).

Example:

```json
{
    "name": "sportscentre",
    "did": "did:jwk:secp256r1",
    "adminToken": "secrettoken",
    "path": "/sportscentre",
    "presentations": ["GC", "ABC", "PID"],
    "metadata": {
        "client_name": "University Sports Centre",
        "description": "Sports Centre credential verification test",
        "logo_uri": "logo-url",
        "location": "Harderwijk"
    }
}
```

This example defines a verifier endpoint for the `sportscentre`. The `adminToken` is used for front-end interaction. The verifier refers to a previously configured `did` using the `did` attribute, which contains an alias. 

## Interfaces

The front-end-facing verifiers can interact with the Veramo-Verifier using their specific administrative `token`. These are the basic endpoints for this api:

`/:instance/api/create-offer/:presentationid`: request a new authorization request object
`/:instance/api/check-offer/:state`: poll for status updates on a previously created authorization request
`/:instance/api/check-status`: request a status update on a specific statuslist entry

To support the Credential Verification process, the Veramo-Verifier has some additional endpoints:

- `/:instance/get-offer/:state`: the endpoint to get the actual Authorization Request Object
- `/:instance/get-presentation/:presentation`: the endpoint to get a specific presentation definition
- `/:instance/response/:state`: the endpoint to which the wallet sends its verification response

## Endpoint definitions

### Create Offer

`/:instance/api/create-offer/:presentationid`

This endpoint creates a new state object for a specific presentation. The presentation must be in the set of allowed presentations for this `instance`, for example, `ABC` or `PID`. This endpoint has a `POST` method, although no actual data is posted at the moment. It has content-type `json` and requires the `Authorization: Bearer <token>` header.

The Veramo-Verifier replies with a response object containing the following data:

```json
{
    "state": "<random state generated by the Veramo-Verifier>",
    "requestUri": "<uri, containing state, to be presented as QR code or link>",
    "checkUri": "<uri to be polled by the front-end-verifier for status updates>"
}
```

### Check Offer

`/:instance/api/check-offer/:state`

This endpoint allows the front-end verifier to poll for status updates with the Veramo-Verifier while the wallet interacts with the agent. It returns the following object:

```json
{
  "status": "AuthorizationRequestCreated",
  "created": "2024-09-13T09:20:49+00:00",
  "lastUpdate": "2024-09-13T09:20:49+00:00"
}
```

The status attribute can be one of the following:

- AuthorizationRequestCreated: object was created, waiting for interaction
- AuthorizationRequestRetrieved: wallet has scanned the code, user interaction required
- ResponseReceived: Verifiable Presentation was returned, data available

When the last status is returned, the response object is extended with the `result` attribute:

```json
{
  "status": "ResponseReceived",
  "created": "2024-09-13T09:20:49+00:00",
  "lastUpdate": "2024-09-13T09:20:49+00:00",
  "result": {
    "state": "cb3349e1-8415-4d96-bd40-d03663836ad5",
    "nonce": "8472d4aa-0429-4084-8596-b6adebf7248c",
    "issuer": "<did key of the VP signer (should be the wallet)>",
    "credentials": {
      "<credential-type-identifier>": [{
        "holder": "<did key of the VC holder (wallet)>",
        "issuerKey": "<did key of the VC issuer>",
        "issuer": "<VC issuer id, which currently equals the issuerKey>",
        "claims": {
          [x:string]: string|number
        },
        "metadata": {
          "statusLists": [{
            "id": "<status list entry id>",
            "type": "<type of this status list>",
            "statusPurpose": "<purpose, one of revocation or suspension>",
            "statusListIndex": "<unique numeric index>",
            "statusListCredential": "<status list credential url>"
          }],
          "evidence": [{<evidence data>}]
        },
        "payload": "<JWT payload content>"
      }]
    }
    "messages": [{
      "code": "<message code>",
      "message": "<message description>",
      [x:string]: "<additional data>"
    }]
  }
}
```

As mentioned above, only one credential is supported at this time, so the `credentials` attribute list only ever contains a single entry.

The `claims` attribute contains the actual claims as present in the Verifiable Credential and need to be interpreted by the front-end-verifier. No data types, etc. are available, except in the relevant issuer metadata. It is assumed the front-end-verifier knows in advance the mark-up required for presenting this specific type of Verifiable Credential.

The `messages` list contains validation and verification messages gathered during parsing of the VerifiablePresentation. The following codes can be returned:

- `INVALID_STATE`: the VP response lists a state that does not match the expected state. No further data is processed
- `INVALID_JWT`: the VP JWT token could not be decoded correctly. No further data is processed
- `UNVERIFIED_JWT`: the VP JWT token could not be verified, probably due to a missing or unverifiable signature
- `NO_CREDENTIALS_FOUND`: the VP JWT did not contain the expected credentials list
- `INVALID_NONCE`: the VP JWT payload did not encode the nonce value that was expected
- `INVALID_PRESENTATION`: an error occurred while decoding and verifying the constitution of the verifiable presentation
- `INVALID_VC`: an error occurred during decoding of the VC JWT
- `VC_NBF_ERROR`: the VC not-before value lies in the future
- `VC_IAT_ERROR`: the VC issued-at value lies in the future
- `VC_EXP_ERROR`: the VC expiry value lies in the past
- `VC_AUD_ERROR`: the VC aud value does not match the issuer did
- `NO_STATUS_LIST`: no status list was assigned to the credential
- `STATUSLIST_UNREACHABLE`: the status list assigned to the credential could not be contacted
- `STATUSLIST_INVALID`: the status list did not properly encode the bit values
- `CREDENTIAL_REVOKED`: the credential was indicated as revoked (bit set on a status list of type revocation)
- `CREDENTIAL_SUSPENDED`: the credential was indicated as suspended (bit set on a status list of type suspension)
- `CREDENTIAL_STATUS_SET`: the credential has its status bit set, but the status list type was not recognised
- `CREDENTIAL_STATUS_OK`: the credential status could be retrieved and the status bit was not set

### Check Status

`/:instance/api/check-status`

This `POST` endpoint allows the front-end verifier to recheck the credentialStatus of a credential. The `POST` data contains the following `json` object:

```json
{
  "statusList": "<status list credential uri>",
  "index": "<credential status list index number>",
  [x:string]: "<undefined additional data>"
}
```

The response is a status message containing a code and a message. The code is as defined above:

- `STATUSLIST_UNREACHABLE`: the status list assigned to the credential could not be contacted
- `STATUSLIST_INVALID`: the status list did not properly encode the bit values
- `CREDENTIAL_REVOKED`: the credential was indicated as revoked (bit set on a status list of type revocation)
- `CREDENTIAL_SUSPENDED`: the credential was indicated as suspended (bit set on a status list of type suspension)
- `CREDENTIAL_STATUS_SET`: the credential has its status bit set, but the status list type was not recognised
- `CREDENTIAL_STATUS_OK`: the credential status could be retrieved and the status bit was not set

The `statusList` and `index` values have to be recovered from the credential statusLists attribute returned when the verification process was completed.

### Get Credential Offer

The link sent to be presented to the wallet points to this endpoint. The wallet can retrieve the proper `Authorization Object` which kicks off the Credential Verification process.

`/:instance/get-offer/:state`

The interface contains a `state` variable to link this interaction with the previously requested offer from the front-end-verifier, allowing the front-end-verifier to retrieve the credential data in the end.

The response object looks similar to the following (JWT payload)

```json
{
  "iat": 1725272520,
  "exp": 1725272640,
  "response_type": "vp_token",
  "scope": "openid",
  "client_id": "<did key of the verifier agent for this instance>",
  "response_uri": "<uri to send the wallet response to (see below)>",
  "response_mode": "direct_post",
  "nonce": "8472d4aa-0429-4084-8596-b6adebf7248c",
  "state": "cb3349e1-8415-4d96-bd40-d03663836ad5",
  "presentation_definition_uri": "<uri on the Veramo Agent to get the presentation request>",
  "client_metadata": { ... }
  },
  "nbf": 1725272520,
  "jti": "9f498f77-a3f3-4991-88aa-917c9fd7c06c",
  "iss": "<did key of the verifier agent for this instance>",
  "sub": "<did key of the verifier agent for this instance>"
}
```

This is actually a self-signed JWT indicating the Veramo Verifier is in control of this key (`iss`, `sub`) and requests the wallet to send the credential(s) as indicated by the presentation to the response_uri.

### Get Presentation Def

`/:instance/get-presentation/:presentation`

This endpoint is stateless and requests the presentation definition as defined by the parameter. Without selective disclosure, any request for a claim in a Verifiable Credential will always yield the entire credential, so the presentation is usually a simple setup that requests a simple, omnipresent field. It looks as follows:

```json
{
  id: 'ABC',
  name: 'Academic Base Credential',
  purpose: 'Identify using your Academic Base Credential',
  input_descriptors: [{
      id: 'ABC',
      name: 'Academic Base Credential',
      purpose: 'Identify using your Academic Base Credential',
      schema: [{
        "uri": "AcademicBaseCredential"
      }],
      "constraints": {
        "fields": [{
          "path": ["$.credentialSubject.given_name"]
        }]
      }
  }]
}
```

In this example, the purpose of the entire presentation is the same as the purpose for requesting the one credential. The `given_name` is requested, which is always present, so the wallet can select all AcademicBaseCredential credentials it has available and allow the user to pick one.

### Receive Response

`/:instance/response/:state`

The wallet sends the final response to this endpoint, which switches the interaction state to `ResponseReceived` and will provide the credential data to the front-end-verifier.

The response object is a html form encoded set of key-values:

```
expires_in: '300'
state: '6c9c611d-ee10-4c9d-9af5-5992ad191019'
presentation_submission: '{
  "id":"grAU7C0oHg2oinn1IAcw6",
  "definition_id":"ABC",
  "descriptor_map":[{
    "id":"ABC",
    "format":"jwt_vp",
    "path":"$",
    "path_nested":{
      "id":"ABC",
      "format":"jwt_vc",
      "path":"$.vp.verifiableCredential[0]"
    }
  }]
}'
vp_token: <JWT>
```

The `presentation_submission` indicates where to find the requested fields in the set of Verifiable Credentials transmitted. It is a response to the `constraints` field in the presentation definition above.

The actual Verifiable Credentials are stored in the `vp_token` attribute. The Veramo-Verifier decodes and verifies the JWT and collects all the claims for the front-end-verifier.

# Changelog / Release Notes

| Version | Commit  | Date       | Comment             |
| ------- | ------- | ---------- | ------------------- |
|         |         | 2025-11-12 | Implementation of encoded private keys. When running this version, make sure the PASSPHRASE environment variable is set. If it is not set, the keys are not encoded with the migration (so remain unchanged). This will work, but encoding manually afterwards is a pain. The easiest way to fix this is to remove the EncKey migration from the `migrations` table, which will retry to encode all private keys. |

