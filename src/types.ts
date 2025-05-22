export interface Message {
    code: string;
    message?: string;

    [x:string]: any;
}

export interface StringKeyedObject {
    [x:string]: object;
}
