import { HdPath } from "@cosmjs/crypto";
/**
 * The Ethermint derivation path in the form `m/44'/60'/0'/0/a`
 * with 0-based account index `a`.
 */
export declare function makeEthermintPath(a: number): HdPath;
/**
 * The Cosmoshub derivation path in the form `m/44'/118'/0'/0/a`
 * with 0-based account index `a`.
 */
export declare function makeCosmoshubPath(a: number): HdPath;
/**
 * A fixed salt is chosen to archive a deterministic password to key derivation.
 * This reduces the scope of a potential rainbow attack to all CosmJS users.
 * Must be 16 bytes due to implementation limitations.
 */
export declare const cosmjsSalt: Uint8Array;
export interface KdfConfiguration {
  /**
   * An algorithm identifier, such as "argon2id" or "scrypt".
   */
  readonly algorithm: string;
  /** A map of algorithm-specific parameters */
  readonly params: Record<string, unknown>;
}
export declare function executeKdf(password: string, configuration: KdfConfiguration): Promise<Uint8Array>;
/**
 * Configuration how to encrypt data or how data was encrypted.
 * This is stored as part of the wallet serialization and must only contain JSON types.
 */
export interface EncryptionConfiguration {
  /**
   * An algorithm identifier, such as "xchacha20poly1305-ietf".
   */
  readonly algorithm: string;
  /** A map of algorithm-specific parameters */
  readonly params?: Record<string, unknown>;
}
export declare const supportedAlgorithms: {
  xchacha20poly1305Ietf: string;
};
export declare function encrypt(
  plaintext: Uint8Array,
  encryptionKey: Uint8Array,
  config: EncryptionConfiguration,
): Promise<Uint8Array>;
export declare function decrypt(
  ciphertext: Uint8Array,
  encryptionKey: Uint8Array,
  config: EncryptionConfiguration,
): Promise<Uint8Array>;
