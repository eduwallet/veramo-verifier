import { Verifier } from './Verifier';
import {
    ClientMetadataOpts,
    PassBy,
    PropertyTarget,
    ResponseType,
    RevocationVerification,
    RP,
    Scope,
    SIOPErrors,
    SubjectType,
    SupportedVersion,
    VerifiedJWT,
    VerifyJwtCallback,
  } from '@sphereon/did-auth-siop'
import { JwtPayload, JwtHeader, parseJWT, SigningAlgo, JwtIssuer } from '@sphereon/oid4vc-common'
import { createJWT, JWTOptions, JWTVerifyOptions, verifyJWT } from 'did-jwt'
import { Resolvable } from 'did-resolver';
import { agent, resolver } from 'agent';
import { IAgent, IKey, IKeyManager } from '@veramo/core';

interface JWT { header: JwtHeader; payload: JwtPayload };

export function createRPInstance(verifier:Verifier, presentationId:string):RP
{
    // based on @sphereon/ssi-sdk.siopv2-oid4vp-rp-auth/RPInstance.ts
    const defaultClientMetadata: ClientMetadataOpts = {
      idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
      responseTypesSupported: [ResponseType.ID_TOKEN],
      client_name: verifier.name,
      vpFormatsSupported: {
        jwt_vc: { alg: ['EdDSA', 'ES256', 'ES256K'] },
        jwt_vp: { alg: ['EdDSA', 'ES256', 'ES256K'] },
      },
      scopesSupported: [Scope.OPENID_DIDAUTHN],
      subjectTypesSupported: [SubjectType.PAIRWISE],
      subject_syntax_types_supported: ['did:web', 'did:jwk', 'did:key', 'did:ion'],
      passBy: PassBy.VALUE,
    }

    const builder = RP.builder({ requestVersion: SupportedVersion.SIOPv2_D12_OID4VP_D20 })
      .withEventEmitter(verifier.eventEmitter)
      .withSessionManager(verifier.sessionManager)
      .withClientMetadata(defaultClientMetadata, PropertyTarget.REQUEST_OBJECT)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withPresentationVerification(verifier.getPresentationVerificationCallback())
      .withPresentationDefinition({ definition: verifier.getPresentation(presentationId)!}, PropertyTarget.REQUEST_OBJECT)
      .withCreateJwtCallback(getCreateJwtCallback(verifier))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver));
    return builder.build();
}

export async function createDidJWT(
    payload: Partial<JwtPayload>,
    { issuer, signer, expiresIn, canonicalize }: JWTOptions,
    header: Partial<JwtPayload>,
): Promise<string> {
    return createJWT(payload, { issuer, signer, expiresIn, canonicalize }, header)
}

async function verifyDidJWT(jwt: string, resolver: Resolvable, options: JWTVerifyOptions): Promise<VerifiedJWT> {
  return verifyJWT(jwt, { ...options, resolver })
}

export function getCreateJwtCallback(verifier:Verifier) {
  return async (jwtIssuer:JwtIssuer, jwt:JWT) => {
    if (jwtIssuer.method === 'did') {
      const header = {
        alg: jwtIssuer.alg,
        kid: verifier.key
      };
      const options = {
        issuer: verifier.identifier!.did,
        signer: wrapSigner(agent, verifier.key!, verifier.signingAlgorithm()),
        expiresIn: 10 * 60,
      }
      return await createDidJWT({ ...jwt.payload }, options, header);
    }
    throw new Error('Not implemented yet')
  }
}

export function getVerifyJwtCallback(
  resolver: Resolvable,
): VerifyJwtCallback {
  return async (jwtVerifier, jwt) => {
    const audience = getAudience(jwt.raw);
    await verifyDidJWT(jwt.raw, resolver, { audience });
    // we can always return true because the verifyDidJWT will throw an error if the JWT is invalid
    return true
  }
}

function wrapSigner(
  agent:IAgent & IKeyManager,
  key: IKey,
  algorithm?: string,
) {
  return async (data: string | Uint8Array): Promise<string> => {
    const result = await agent.keyManagerSign({ keyRef: key.kid, data: <string>data, algorithm })
    return result
  }
}

function getAudience(jwt: string) {
  const { payload } = parseJWT(jwt)
  if (!payload) {
    throw new Error(SIOPErrors.NO_AUDIENCE)
  } else if (!payload.aud) {
    return undefined
  } else if (Array.isArray(payload.aud)) {
    throw new Error(SIOPErrors.INVALID_AUDIENCE)
  }

  return payload.aud
}