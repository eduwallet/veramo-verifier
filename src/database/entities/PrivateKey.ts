import { Entity, Column, PrimaryColumn, BaseEntity } from 'typeorm'
import { encrypt, decrypt } from '@futuretense/secret-box';
import { fromString, toString } from "uint8arrays";
import crypto from 'crypto';

@Entity('private-key')
export class PrivateKey extends BaseEntity {
  @PrimaryColumn('varchar')
    // @ts-ignore
  alias: string

  @Column('varchar')
    // @ts-ignore
  type: string

  @Column('varchar')
    // @ts-ignore
  privateKeyHex: string

  @Column('varchar')
    // @ts-ignore
  seed: string

  async decodeKey():Promise<string> {
    if (!this.seed || this.seed.length == 0 || (process.env.PASSPHRASE ?? '').length == 0) {
      return this.privateKeyHex;
    }
    const seed = fromString(this.seed, 'hex');
    const encoded = fromString(this.privateKeyHex, 'hex');
    return toString(await decrypt(encoded, fromString(process.env.PASSPHRASE ?? ''), seed, true), 'hex');
  }

  async encodeKey(key:string) {
    if ((process.env.PASSPHRASE ?? '').length > 0) {
      const seed = fromString(this.seed, 'hex');
      const secret = fromString(key, 'hex');
      this.privateKeyHex = toString(await encrypt(secret, fromString(process.env.PASSPHRASE ?? ''), seed, true), 'hex');
    }
  }

  setSeed() {
    this.seed = crypto.randomBytes(32).toString('hex');
  }

}
