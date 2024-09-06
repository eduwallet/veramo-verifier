import { PEX } from '@sphereon/pex';
import { IPresentation, JWTVerified, PresentationSubmission as PEXPresentationSubmission, PresentationDefinitionV2, verifyJWT } from 'externals';
import { resolver } from 'agent';
// https://identity.foundation/presentation-exchange/spec/v2.0.0/
// Implementation of presentation exchange validation

interface ClaimList {
    [x:string]:string|number;
}

export interface ExtractedCredential {
    issuer: string;
    issuedAt?: string;
    holder: string;
    aud?: string;
    nbf?: number;

    claims: ClaimList;
}

export class PresentationSubmission
{
    public presentation:IPresentation;
    public submission:PEXPresentationSubmission;
    public definition:PresentationDefinitionV2;
    public pex:PEX;
    public credentials:ExtractedCredential[];

    public constructor(presentation:IPresentation, definition:PresentationDefinitionV2, submission: PEXPresentationSubmission)
    {
        this.presentation = presentation;
        this.submission = submission;
        this.definition = definition as PresentationDefinitionV2;
        this.pex = new PEX();
        this.credentials = [];
    }

    public async verify():Promise<boolean>
    {
        // extract the credentials from the presentation. 
        for (const jwt of this.presentation.verifiableCredential!) {
            const decoded = await verifyJWT(
                jwt as string,
                {
                    resolver: resolver
                });
            if (!decoded.verified) {
                return false;                
            }
            else {
                const ec:ExtractedCredential = this.extractVCJsonCredential(decoded);
                this.credentials.push(ec);
            }
        }


        const { value, warnings, errors } = this.pex.evaluatePresentation(this.definition, this.presentation, { presentationSubmission: this.submission });
        if(errors && errors.length > 0) {
            return false;
        }

        // It seems the whole implementation of presentationSubmission does not work (or at least the mutual interpretation does not match)
        // When requesting $.credentialSubject.given_name, the return path is '$', with a path_nested $.vp.verifiableCredential[0]
        // These paths both seem to point to the whole credential and not to the specific claim inside the credential.
        // As long as the whole process does not support requesting more than 1 credential (DIIP restriction), it does not really matter
        // of course: we always get the whole credential and the back-end can try and find out what to do with it.

        return true;
    }

    private extractVCJsonCredential(jwt:JWTVerified):ExtractedCredential
    {
        var ec:ExtractedCredential= {
            issuer: jwt.issuer,
            holder: jwt.payload.sub!,
            claims: {}
        };

        if (jwt.payload.nbf) {
            ec.nbf = jwt.payload.nbf;
        }
        if (jwt.payload.issuanceDate) {
            ec.issuedAt = jwt.payload.issuanceDate;
        }

        if (jwt.payload.credentialSubject) {
            for (const k of Object.keys(jwt.payload.credentialSubject)) {
                ec.claims[k] = jwt.payload.credentialSubject[k];
            }
        }

        return ec;
    }
}