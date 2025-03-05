import {
  IKey,
  KEY_ALG_MAPPING,
  ManagedKeyInfo,
  MinimalImportableKey,
  RequireOnly,
  TKeyType,
} from '@veramo/core-types'
import {
  AbstractKeyManagementSystem,
  AbstractPrivateKeyStore,
  Eip712Payload,
  ManagedPrivateKey,
} from '@veramo/key-manager'

import Debug from 'debug'
import { CryptoKey } from '../../crypto/CryptoKey';
import { Factory } from '../../crypto/Factory'

const debug = Debug('eduwallet:kms:local')

/**
 * This is an implementation of {@link @veramo/key-manager#AbstractKeyManagementSystem | AbstractKeyManagementSystem}
 * that uses a local {@link @veramo/key-manager#AbstractPrivateKeyStore | AbstractPrivateKeyStore} to hold private key
 * material.
 *
 * The key material is used to provide local implementations of various cryptographic algorithms.
 *
 * @public
 */
export class KeyManagementSystem extends AbstractKeyManagementSystem {
  private readonly keyStore: AbstractPrivateKeyStore

  constructor(keyStore: AbstractPrivateKeyStore) {
    super()
    this.keyStore = keyStore
  }

  async importKey(args: Omit<MinimalImportableKey, 'kms'>): Promise<ManagedKeyInfo> {
    if (!args.type || !args.privateKeyHex) {
      throw new Error('invalid_argument: type and privateKeyHex are required to import a key')
    }
    const cryptoKey = Factory.createFromType(args.type, args.privateKeyHex);
    const managedKey:ManagedKeyInfo = this.asManagedKeyInfo(cryptoKey, args.kid);
    await this.keyStore.importKey({ alias: managedKey.kid, ...args })
    debug('imported key', managedKey.type, managedKey.publicKeyHex)
    return managedKey as ManagedKeyInfo;
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    const privateKeys = await this.keyStore.listKeys({})
    const managedKeys = privateKeys.map((key) => {
      const ckey = Factory.createFromType(key.type, key.privateKeyHex);
      return this.asManagedKeyInfo(ckey);
    });
    return managedKeys
  }

  async createKey({ type }: { type: TKeyType }): Promise<ManagedKeyInfo> {
    let cryptoKey = Factory.createFromType(type as string);
    cryptoKey.createPrivateKey();
    return this.asManagedKeyInfo(cryptoKey);
  }

  async deleteKey(args: { kid: string }) {
    return await this.keyStore.deleteKey({ alias: args.kid })
  }

  async sign({
    keyRef,
    algorithm,
    data,
  }: {
    keyRef: Pick<IKey, 'kid'>
    algorithm?: string
    data: Uint8Array
  }): Promise<string> {
    let managedKey: ManagedPrivateKey
    try {
      managedKey = await this.keyStore.getKey({ alias: keyRef.kid })
    } catch (e) {
      throw new Error(`key_not_found: No key entry found for kid=${keyRef.kid}`)
    }

    let cryptoKey = Factory.createFromType(managedKey.type, managedKey.privateKeyHex);
    if (!algorithm) {
      algorithm = cryptoKey.algorithms()[0];
    }
    return await cryptoKey.sign(algorithm, data);
  }

  /**
   * Converts a CryptoKey to {@link @veramo/core-types#ManagedKeyInfo}
   */
  private asManagedKeyInfo(ckey:CryptoKey, kid?:string): ManagedKeyInfo {
    const publicKeyHex = ckey.publicKeyHex();
    return {
      type: ckey.keyType as TKeyType,
      kid: kid || publicKeyHex,
      publicKeyHex,
      ...(ckey.hasPrivateKey() && { privateKeyHex: ckey.exportPrivateKey()}),
      meta: {
        algorithms: ckey.algorithms()
      }
    } as ManagedKeyInfo;
  }

  async sharedSecret(args: {
    myKeyRef: Pick<IKey, 'kid'>
    theirKey: Pick<IKey, 'type' | 'publicKeyHex'>
  }): Promise<string>
  {
    throw new Error("KeyManagementSystem::sharedSecret not implemented");
  }  
}
