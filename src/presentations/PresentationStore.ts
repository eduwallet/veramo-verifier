import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from "@utils/resolveConfPath";

export interface ClaimPresentation {
    id?:string;
    path: string[];
}

export interface CredentialPresentation {
    id: string;
    format: string;
    multiple?:boolean;
    require_cryptographic_holder_binding?: boolean;
    meta: any;
    claims: ClaimPresentation[];
}

export interface CredentialSet {
    options: string[];
    required?:boolean;
}

export interface PresentationQuery {
    credentials: CredentialPresentation[];
    credential_sets: CredentialSet[];
}

export interface PresentationDefinition {
    id: string;
    name: string;
    purpose: string;
    query?: any;
    input_descriptors?:any;
}

interface StoreType {
    [x:string]: PresentationDefinition;
}

var _store:StoreType = {};

export function getPresentationStore() {
    return _store;
}

export async function initialisePresentationStore() {
    const options = loadJsonFiles<PresentationDefinition>({path: resolveConfPath('presentations')});
    for (const opt of options.asArray) {
        _store[opt.id] = opt;
    }   
}
