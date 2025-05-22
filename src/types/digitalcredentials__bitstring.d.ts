declare module '@digitalcredentials/bitstring' {
    export class Bitstring {
      static fromBits(bits: number[]): Bitstring;
      static async decodeBits({encoded:string}):Uint8Array;
      constructor({length,buffer,leftToRightIndexing,littleEndianBits}:{
        length?:number;
        buffer?:Uint8Array,
        leftToRightIndexing?:boolean;
        littleEndianBits?:boolean;
      });
      toBits(): number[];
      toBytes(): Uint8Array;
      toString(): string;
      length(): number;
      get(index: number): boolean;
      set(index: number, value: boolean): void;
    }
  }