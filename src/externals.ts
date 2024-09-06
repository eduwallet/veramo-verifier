import type { PresentationSubmission, PresentationDefinitionV2 } from '@sphereon/pex-models';
import type { W3CVerifiableCredential, IPresentation } from '@sphereon/ssi-types';
import { createJWT, verifyJWT } from 'did-jwt';
import type {JWTVerified } from 'did-jwt';

export {
    createJWT,
    IPresentation,
    JWTVerified,
    PresentationDefinitionV2,
    PresentationSubmission,
    verifyJWT,
    W3CVerifiableCredential,
};
