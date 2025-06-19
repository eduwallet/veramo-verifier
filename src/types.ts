export interface Message {
    code: string;
    message?: string;

    [x:string]: any;
}

export interface StringKeyedObject {
    [x:string]: object;
}

export interface ApiResponseCredential {
    format:string;
    claims:any;
    issuer: string;
    issuerKey: string;
    holder: string;
    statusLists: any[];
    metadata: any;
    payload: any;
}