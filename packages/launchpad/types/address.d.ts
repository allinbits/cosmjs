import { PubKey } from "./types";
export declare function rawEthSecp256k1PubkeyToAddress(pubkeyRaw: Uint8Array, prefix: string): string;
export declare function rawSecp256k1PubkeyToAddress(pubkeyRaw: Uint8Array, prefix: string): string;
export declare function pubkeyToAddress(pubkey: PubKey, prefix: string): string;
