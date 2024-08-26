import { IIdentifier, IKey } from "@veramo/core";
import { agent } from '../agent';
import { PresentationVerificationResult, RP} from '@sphereon/did-auth-siop'
import { getKey } from '@sphereon/ssi-sdk-ext.did-utils'
import { createRPInstance } from './createRPInstance'
import { Router } from "express";

export interface VerifierOptions {
    name:string;
    did:string;
    adminToken:string;
    path:string;
}

export class Verifier {
    public name:string;
    public did:string;
    public adminToken:string;
    public identifier:IIdentifier|undefined;
    public key:IKey|undefined;
    public rp:RP|undefined;
    public router:Router|undefined;
    public path:string;

    public constructor(opts:VerifierOptions)
    {
        this.name = opts.name;
        this.did = opts.did;
        this.adminToken = opts.adminToken;
        this.path = opts.path;
    }

    public async initialise() {
        this.identifier = await agent.didManagerGet({did: this.did});
        this.key = await getKey({identifier: this.identifier, vmRelationship: "verificationMethod"}, {agent});
        this.rp = createRPInstance(this);
    }

    public getPresentationVerificationCallback() {
        return async (args:any):Promise<PresentationVerificationResult> => {
            return {
                verified: true
            }
        };
    }
}