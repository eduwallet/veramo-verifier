import { Verifier } from './Verifier';
import {
    ClientMetadataOpts,
    InMemoryRPSessionManager,
    PassBy,
    PropertyTarget,
    ResponseMode,
    ResponseType,
    RevocationVerification,
    RP,
    Scope,
    SubjectType,
    SupportedVersion,
  } from '@sphereon/did-auth-siop'
import {SigningAlgo } from '@sphereon/oid4vc-common';
import { EventEmitter } from 'events'

export function createRPInstance(verifier:Verifier):RP
{
    const did = verifier.did; 
    const defaultClientMetadata: ClientMetadataOpts = {
      idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
      responseTypesSupported: [ResponseType.ID_TOKEN],
      client_name: verifier.name,
      vpFormatsSupported: {
        jwt_vc: { alg: ['EdDSA', 'ES256K'] },
        jwt_vp: { alg: ['ES256K', 'EdDSA'] },
      },
      scopesSupported: [Scope.OPENID_DIDAUTHN],
      subjectTypesSupported: [SubjectType.PAIRWISE],
      subject_syntax_types_supported: ['did:web', 'did:jwk', 'did:key', 'did:ion'],
      passBy: PassBy.VALUE,
    }

    const eventEmitter = new EventEmitter();
    const builder = RP.builder({ requestVersion: SupportedVersion.SIOPv2_D12_OID4VP_D20 })
      .withScope('openid', PropertyTarget.REQUEST_OBJECT)
      .withResponseMode(ResponseMode.POST)
      .withResponseType(ResponseType.VP_TOKEN, PropertyTarget.REQUEST_OBJECT)
      .withClientId(did, PropertyTarget.REQUEST_OBJECT)
      // todo: move to options fill/correct method
      .withSupportedVersions(
        [SupportedVersion.SIOPv2_D12_OID4VP_D20],
      ) 
      .withEventEmitter(eventEmitter)
      .withSessionManager(new InMemoryRPSessionManager(eventEmitter))
      .withClientMetadata(defaultClientMetadata, PropertyTarget.REQUEST_OBJECT)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withPresentationVerification(verifier.getPresentationVerificationCallback());
  
    return builder.build();
}