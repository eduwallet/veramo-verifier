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
```

## Installation

Run `yarn` to install the basic packages:

`yarn install`


## Interfaces

The verifying entity can request a verification code up front and present this in a QR code to the wallet/holder.
This request contains the final callback URL that is called by the agent with the data and metadata from the verification flow.
Verifying entities can include opaque verification_state and specify the credential and claims they want presented.

Currently, only one credential can be requested at a time.

