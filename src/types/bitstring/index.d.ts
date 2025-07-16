declare module '@digitalcredentials/bitstring';

interface ConstructorOptions {
    length:number
    buffer:Uint8Array
    leftToRightIndexing:boolean
    littleEndianBits: boolean
};

export class Bitstring {
    constructor(options:ConstructorOptions);
    public set(position:number, on:boolean):void;
    public get(position:number):boolean;
    public async encodeBits():string;
    public async decodeBits({string}):Uint8Array;
    public async compressBits():Uint8Array;
    static public async uncompressBits({Uint8Array}):Uint8Array;
    

}