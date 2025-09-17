// https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.2

export interface PresentationObject {
    [x:string]:any;
}

export type Presentation = PresentationObject|PresentationObject[]|string|string[];
export interface PresentationResult {
    [x:string]:Presentation;
}

export interface AuthorizationResponse
{
    vp_token: PresentationResult;
    code?:string;
    id_token?:string;
    iss?:string;
    state?:string;
}
