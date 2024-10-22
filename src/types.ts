export interface Message {
    code: string;
    message?: string;

    [x:string]: any;
}
