export interface Message {
    code: string;
    message?: string;

    [x:string]: any;
}

export interface DCQL {
    credentials: any[];
    credential_sets?: any[];
}