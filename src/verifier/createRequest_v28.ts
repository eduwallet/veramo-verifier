import { getBaseUrl } from "@utils/getBaseUrl";
import { RP } from "./RP";
import { replaceParamsInUrl } from "@utils/replaceParamsInUrl";
import { response_path } from "server/createRoutesForVerifier";

export function createRequest_v28(rp:RP, dcql:any)
{
    const response_uri = getBaseUrl() + '/' + rp.verifier.name + replaceParamsInUrl(response_path, {state:rp.session.uuid});
    return {
        // basic RequestObject attributes
        "response_type": 'vp_token', // instructs the wallet to return a vp_token
        "response_mode": "direct_post", // default is using query or fragment elements in the callback
        "state": rp.session.uuid,
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.9.3
        // use the decentralized_identifier prefix to pass on our did key
        "client_id": 'decentralized_identifier:' + rp.verifier.clientId(),
        //"scope": // used for predefined dcql queries
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#section-8.2
        // "response_uri REQUIRED when direct_post is used, redirect_uri MUST NOT be present"
        "response_uri": response_uri,
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.2
        // "This endpoint to which the Self-Issued OP shall deliver the authentication result is conveyed in the standard parameter redirect_uri."
        //"redirect_uri": response_uri,
        "client_id_scheme": "did", // UniMe workaround
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
        // "The RP MUST send a nonce"
        "nonce": rp.session.data.nonce,
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.1
        // "The aud Claim MUST equal to the issuer Claim value, when Dynamic Self-Issued OP Discovery is performed."
        "aud": rp.verifier.clientId(),

        // AuthorizationRequest attributes
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
        "client_metadata": rp.clientMetadata(),
        "id_token_type": "attester_signed_id_token subject_signed_id_token",
        "dcql_query": dcql
    }
}