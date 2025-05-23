import { IAgentContext, IIdentifier, IKey, IKeyManager, IService, RequireOnly, MinimalImportableKey } from '@veramo/core-types'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { Factory } from '@muisit/cryptokey';

import Debug from 'debug'
import { IKeyManagerCreateArgs } from '@veramo/core';

const debug = Debug('verifier:did-jwk')

type IContext = IAgentContext<IKeyManager>
type CreateKeyDidOptions = {
  keyType?: string;
  privateKeyHex?: string
}

export class JwkDIDProvider extends AbstractIdentifierProvider {
  private defaultKms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
    { kms, options }: { kms?: string; options?: CreateKeyDidOptions },
    context: IContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const keyType = (options?.keyType && options.keyType) || 'Ed25519'
    const key = await this.importOrGenerateKey(
      {
        kms: kms || this.defaultKms,
        options: {
          keyType,
          ...(options?.privateKeyHex && { privateKeyHex: options.privateKeyHex }),
        },
      },
      context,
    )

    const cryptoKey = await Factory.createFromType(key.type, key.privateKeyHex);
    cryptoKey.setPublicKey(key.publicKeyHex);
    const methodSpecificId:string = await Factory.toDIDJWK(cryptoKey);

    const identifier: Omit<IIdentifier, 'provider'> = {
      did: methodSpecificId,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
    }
    debug('Created', identifier.did)
    return identifier
  }

  async updateIdentifier(
    args: {
      did: string
      kms?: string | undefined
      alias?: string | undefined
      options?: any
    },
    context: IAgentContext<IKeyManager>,
  ): Promise<IIdentifier> {
    throw new Error('JwkDIDProvider updateIdentifier not implemented.')
  }

  async deleteIdentifier(identifier: IIdentifier, context: IContext): Promise<boolean> {
    for (const { kid } of identifier.keys) {
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey(
    { identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('JwkDIDProvider addKey not implemented')
  }

  async addService(
    { identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('JwkDIDProvider addService not implemented')
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('JwkDIDProvider removeKey not implemented')
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('JwkDIDProvider removeService not implemented')
  }

  private async importOrGenerateKey(
    args: {
      kms: string
      options: RequireOnly<CreateKeyDidOptions, 'keyType'>
    },
    context: IContext,
  ): Promise<IKey> {
    if (args.options.privateKeyHex) {
      return context.agent.keyManagerImport({
        kms: args.kms || this.defaultKms,
        type: args.options.keyType,
        privateKeyHex: args.options.privateKeyHex,
      } as MinimalImportableKey)
    }
    return context.agent.keyManagerCreate({
      kms: args.kms || this.defaultKms,
      type: args.options.keyType,
    } as IKeyManagerCreateArgs)
  }
}
