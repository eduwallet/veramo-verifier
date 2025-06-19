import { ApiResponseCredential } from "types";

export abstract class Credential {
    public format:string = '';
    public data:any = {};
    public issuerName:string = '';
    public issuerKey:string = '';
    public holder:string = '';
    public statusLists:any[] = [];
    public metadata:any = {};
    public payload:any = {};

    abstract parse(credential:any):void;
    abstract verify(): Promise<boolean>;

    public export(): ApiResponseCredential
    {
        return {
            format: this.format,
            claims: this.data,
            issuer: this.issuerName,
            issuerKey: this.issuerKey,
            holder: this.holder,
            statusLists: this.statusLists,
            metadata: this.metadata,
            payload: this.payload
        }
    }
}