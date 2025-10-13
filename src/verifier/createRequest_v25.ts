import Debug from 'debug';
const debug = Debug('verifier:protocol');

import { replaceParamsInUrl } from "@utils/replaceParamsInUrl";
import { RP } from "./RP";
import { get_presentation_path, response_path } from "server/createRoutesForVerifier";
import { getBaseUrl } from "@utils/getBaseUrl";

// This creates a request following the version 25 spec which still supports presentations
export function createRequest_v25(rp:RP)
{
    debug('Creating v25 authorization request using input descriptor/PEX')   ;
    const presentation_uri = getBaseUrl() + '/' + rp.verifier.name + replaceParamsInUrl(get_presentation_path, {presentationid: rp.presentation.id});
    const response_uri = getBaseUrl() + '/' + rp.verifier.name + replaceParamsInUrl(response_path, {presentationid: rp.presentation.id, state:rp.state});
    return {
        // basic RequestObject attributes
        "scope": "openid",
        "response_type": 'vp_token id_token', // instructs the wallet to return a vp_token response with a SIOP id_token
        "response_mode": "direct_post", // default is using query or fragment elements in the callback
        "state": rp.state,
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-25.html#section-5.10.4
        // because we use a did as client identifier scheme, we must NOT prefix it with did:
        "client_id": rp.verifier.clientId(),
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html#section-7.2
        // "required when direct_post is used, redirect_uri must NOT be present"
        "response_uri": response_uri,
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.2
        // "This endpoint to which the Self-Issued OP shall deliver the authentication result is conveyed in the standard parameter redirect_uri."
        // "redirect_uri": response_uri,
        "client_id_scheme": "did", // UniMe workaround
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
        // "The RP MUST send a nonce"
        "nonce": rp.nonce,
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.1
        // "The aud Claim MUST equal to the issuer Claim value, when Dynamic Self-Issued OP Discovery is performed."
        "aud": rp.verifier.clientId(),

        // AuthorizationRequest attributes
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
        "client_metadata": rp.clientMetadata(),
        "id_token_type": "attester_signed_id_token subject_signed_id_token",
        "presentation_definition_uri": presentation_uri,
    }
}