import { AbstractKeyStore, AbstractKeyManagementSystem } from '@veramo/key-manager'
import {
  IAgentPlugin,
  IKey,
  IKeyManager,
  IKeyManagerCreateArgs,
  IKeyManagerDecryptJWEArgs,
  IKeyManagerDeleteArgs,
  IKeyManagerEncryptJWEArgs,
  IKeyManagerGetArgs,
  IKeyManagerSharedSecretArgs,
  IKeyManagerSignArgs,
  IKeyManagerSignEthTXArgs,
  IKeyManagerSignJWTArgs,
  ManagedKeyInfo,
  MinimalImportableKey
} from '@veramo/core-types'
import { schema } from '@veramo/core-types'
import * as u8a from 'uint8arrays'

/**
 * Agent plugin that implements {@link @veramo/core-types#IKeyManager} methods.
 *
 * This plugin orchestrates various implementations of {@link AbstractKeyManagementSystem}, using a KeyStore to
 * remember the link between a key reference, its metadata, and the respective key management system that provides the
 * actual cryptographic capabilities.
 *
 * The methods of this plugin are used automatically by other plugins, such as
 * {@link @veramo/did-manager#DIDManager | DIDManager},
 * {@link @veramo/credential-w3c#CredentialPlugin | CredentialPlugin} to
 * perform their required cryptographic operations using the managed keys.
 *
 * Reimplemented to remove superfluous methods and dependencies
 * 
 * @public
 */
export class KeyManager implements IAgentPlugin {
  /**
   * Plugin methods
   * @public
   */
  readonly methods: IKeyManager

  readonly schema = schema.IKeyManager

  private store: AbstractKeyStore
  private kms: Record<string, AbstractKeyManagementSystem>

  constructor(options: { store: AbstractKeyStore; kms: Record<string, AbstractKeyManagementSystem> }) {
    this.store = options.store
    this.kms = options.kms
    this.methods = {
      keyManagerGetKeyManagementSystems: this.keyManagerGetKeyManagementSystems.bind(this),
      keyManagerCreate: this.keyManagerCreate.bind(this),
      keyManagerGet: this.keyManagerGet.bind(this),
      keyManagerDelete: this.keyManagerDelete.bind(this),
      keyManagerImport: this.keyManagerImport.bind(this),
      keyManagerEncryptJWE: this.keyManagerEncryptJWE.bind(this),
      keyManagerDecryptJWE: this.keyManagerDecryptJWE.bind(this),
      keyManagerSignJWT: this.keyManagerSignJWT.bind(this),
      keyManagerSignEthTX: this.keyManagerSignEthTX.bind(this),
      keyManagerSign: this.keyManagerSign.bind(this),
      keyManagerSharedSecret: this.keyManagerSharedSecret.bind(this),
    }
  }

  private getKms(name: string): AbstractKeyManagementSystem {
    const kms = this.kms[name]
    if (!kms) {
      throw Error(`invalid_argument: This agent has no registered KeyManagementSystem with name='${name}'`)
    }
    return kms
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerGetKeyManagementSystems} */
  async keyManagerGetKeyManagementSystems(): Promise<Array<string>> {
    return Object.keys(this.kms)
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerCreate} */
  async keyManagerCreate(args: IKeyManagerCreateArgs): Promise<ManagedKeyInfo> {
    const kms = this.getKms(args.kms)
    const partialKey = await kms.createKey({ type: args.type, meta: args.meta })
    const key: IKey = { ...partialKey, kms: args.kms }
    if (args.meta || key.meta) {
      key.meta = { ...args.meta, ...key.meta }
    }
    await this.store.importKey(key)
    if (key.privateKeyHex) {
      delete key.privateKeyHex
    }
    return key
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerGet} */
  async keyManagerGet({ kid }: IKeyManagerGetArgs): Promise<IKey> {
    return this.store.getKey({ kid })
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerDelete} */
  async keyManagerDelete({ kid }: IKeyManagerDeleteArgs): Promise<boolean> {
    const key = await this.store.getKey({ kid })
    const kms = this.getKms(key.kms)
    await kms.deleteKey({ kid })
    return this.store.deleteKey({ kid })
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerImport} */
  async keyManagerImport(key: MinimalImportableKey): Promise<ManagedKeyInfo> {
    const kms = this.getKms(key.kms)
    const managedKey = await kms.importKey(key)
    const { meta } = key
    const importedKey = { ...managedKey, meta: { ...meta, ...managedKey.meta }, kms: key.kms }
    await this.store.importKey(importedKey)
    return importedKey
  }

  /* not implemented */
  async keyManagerEncryptJWE({ kid, to, data }: IKeyManagerEncryptJWEArgs): Promise<string> {
    throw new Error("KeyManager::encryptJWE not implemented");
  }

  /* not implemented */
  async keyManagerDecryptJWE({ kid, data }: IKeyManagerDecryptJWEArgs): Promise<string> {
    throw new Error("KeyManager::decryptJWE not implemented");
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerSignJWT} */
  async keyManagerSignJWT({ kid, data }: IKeyManagerSignJWTArgs): Promise<string> {
      if (typeof data !== 'string') {
          data = u8a.toString(data, 'base16');
      }
      return this.keyManagerSign({ keyRef: kid, data, encoding: 'utf-8' })
  }

  /** {@inheritDoc @veramo/core-types#IKeyManager.keyManagerSign} */
  async keyManagerSign(args: IKeyManagerSignArgs): Promise<string> {
    const { keyRef, data, algorithm, encoding, ...extras } = { encoding: 'utf-8', ...args }
    const keyInfo: ManagedKeyInfo = await this.store.getKey({ kid: keyRef })
    let dataBytes
    if (typeof data === 'string') {
      if (encoding === 'base16' || encoding === 'hex') {
        const preData = data.startsWith('0x') ? data.substring(2) : data
        dataBytes = u8a.fromString(preData, 'base16')
      } else {
        dataBytes = u8a.fromString(data, <'utf-8'>encoding)
      }
    } else {
      dataBytes = data
    }
    const kms = this.getKms(keyInfo.kms)
    return kms.sign({ keyRef: keyInfo, algorithm, data: dataBytes, ...extras })
  }

  /* not implemented */
  async keyManagerSignEthTX({ kid, transaction }: IKeyManagerSignEthTXArgs): Promise<string> {
      throw new Error("KeyManager::signEthTX not implemented");
  }

  /*not implemented */
  async keyManagerSharedSecret(args: IKeyManagerSharedSecretArgs): Promise<string> {
    throw new Error("KeyManager::sharedSecret not implemented");
  }
}
