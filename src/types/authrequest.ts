export interface AuthorizationRequest
{
    response_type:string; // 'code', 'token'
    response_mode?:string; // query, fragment, form_post, web_message
    client_id:string;
    redirect_uri?:string;
    scope?:string;
    state?:string;

}