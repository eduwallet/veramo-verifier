export interface AuthorizationRequest
{
    response_type:string; // 'code', 'token'
    response_mode?:string; // query, fragment, form_post, web_message
    client_id:string;
    redirect_uri?:string;
    scope?:string;
    // "The Verifier MAY use the state Authorization Request parameter to add appropriate data to the Authorization Response"
    state?:string;

}