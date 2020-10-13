import { HdPath } from "@cosmjs/crypto";
import { StdSignDoc } from "./encoding";
import { Secp256k1Wallet } from "./secp256k1wallet";
import { AccountData, SignResponse } from "./signer";
export declare class EthSecp256k1Wallet extends Secp256k1Wallet {
  /**
   * Restores an Ethermint wallet from the given BIP39 mnemonic.
   *
   * @param mnemonic Any valid English mnemonic.
   * @param hdPath The BIP-32/SLIP-10 derivation path. Defaults to the Ethermint path `m/44'/60'/0'/0/0`.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "eth".
   */
  static fromMnemonic(mnemonic: string, hdPath?: HdPath, prefix?: string): Promise<EthSecp256k1Wallet>;
  /**
   * Generates a new Ethermint wallet with a BIP39 mnemonic of the given length.
   *
   * @param length The number of words in the mnemonic (12, 15, 18, 21 or 24).
   * @param hdPath The BIP-32/SLIP-10 derivation path. Defaults to the Ethermint path `m/44'/60'/0'/0/0`.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "eth".
   */
  static generate(
    length?: 12 | 15 | 18 | 21 | 24,
    hdPath?: HdPath,
    prefix?: string,
  ): Promise<EthSecp256k1Wallet>;
  /**
   * Restores a wallet from an encrypted serialization.
   *
   * @param password The user provided password used to generate an encryption key via a KDF.
   *                 This is not normalized internally (see "Unicode normalization" to learn more).
   */
  static deserialize(serialization: string, password: string): Promise<EthSecp256k1Wallet>;
  /**
   * Restores a wallet from an encrypted serialization.
   *
   * This is an advanced alternative to calling `deserialize(serialization, password)` directly, which allows
   * you to offload the KDF execution to a non-UI thread (e.g. in a WebWorker).
   *
   * The caller is responsible for ensuring the key was derived with the given KDF configuration. This can be
   * done using `extractKdfConfiguration(serialization)` and `executeKdf(password, kdfConfiguration)` from this package.
   */
  static deserializeWithEncryptionKey(
    serialization: string,
    encryptionKey: Uint8Array,
  ): Promise<EthSecp256k1Wallet>;
  protected static deserializeTypeV1(serialization: string, password: string): Promise<EthSecp256k1Wallet>;
  protected get address(): string;
  getAccounts(): Promise<readonly AccountData[]>;
  sign(signerAddress: string, signDoc: StdSignDoc): Promise<SignResponse>;
}
