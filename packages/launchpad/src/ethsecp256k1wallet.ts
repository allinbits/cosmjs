import {
  Bip39,
  EnglishMnemonic,
  HdPath,
  Keccak256,
  Random,
  Secp256k1,
  Slip10,
  Slip10Curve, stringToPath,
} from "@cosmjs/crypto";
import { fromBase64, fromUtf8 } from "@cosmjs/encoding";
import { assert, isNonNullObject } from "@cosmjs/utils";

import { rawEthSecp256k1PubkeyToAddress } from "./address";
import { serializeSignDoc, StdSignDoc } from "./encoding";
import { isSecp256k1DerivationJson, serializationTypeV1, Secp256k1Wallet } from "./secp256k1wallet";
import { encodeEthSecp256k1Signature } from "./signature";
import { AccountData, SignResponse } from "./signer";
import { decrypt, executeKdf, makeEthermintPath } from "./wallet";

export class EthSecp256k1Wallet extends Secp256k1Wallet {
  /**
   * Restores an Ethermint wallet from the given BIP39 mnemonic.
   *
   * @param mnemonic Any valid English mnemonic.
   * @param hdPath The BIP-32/SLIP-10 derivation path. Defaults to the Ethermint path `m/44'/60'/0'/0/0`.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "eth".
   */
  public static async fromMnemonic(
    mnemonic: string,
    hdPath: HdPath = makeEthermintPath(0),
    prefix = "eth",
  ): Promise<EthSecp256k1Wallet> {
    const mnemonicChecked = new EnglishMnemonic(mnemonic);
    const seed = await Bip39.mnemonicToSeed(mnemonicChecked);
    const { privkey } = Slip10.derivePath(Slip10Curve.Secp256k1, seed, hdPath);
    const uncompressed = (await Secp256k1.makeKeypair(privkey)).pubkey;
    return new EthSecp256k1Wallet(
      mnemonicChecked,
      hdPath,
      privkey,
      Secp256k1.compressPubkey(uncompressed),
      prefix,
    );
  }

  /**
   * Generates a new Ethermint wallet with a BIP39 mnemonic of the given length.
   *
   * @param length The number of words in the mnemonic (12, 15, 18, 21 or 24).
   * @param hdPath The BIP-32/SLIP-10 derivation path. Defaults to the Ethermint path `m/44'/60'/0'/0/0`.
   * @param prefix The bech32 address prefix (human readable part). Defaults to "eth".
   */
  public static async generate(
    length: 12 | 15 | 18 | 21 | 24 = 12,
    hdPath: HdPath = makeEthermintPath(0),
    prefix = "eth",
  ): Promise<EthSecp256k1Wallet> {
    const entropyLength = 4 * Math.floor((11 * length) / 33);
    const entropy = Random.getBytes(entropyLength);
    const mnemonic = Bip39.encode(entropy);
    return EthSecp256k1Wallet.fromMnemonic(mnemonic.toString(), hdPath, prefix);
  }

  /**
   * Restores a wallet from an encrypted serialization.
   *
   * @param password The user provided password used to generate an encryption key via a KDF.
   *                 This is not normalized internally (see "Unicode normalization" to learn more).
   */
  public static async deserialize(serialization: string, password: string): Promise<EthSecp256k1Wallet> {
    const root = JSON.parse(serialization);
    if (!isNonNullObject(root)) throw new Error("Root document is not an object.");
    switch ((root as any).type) {
      case serializationTypeV1:
        return EthSecp256k1Wallet.deserializeTypeV1(serialization, password);
      default:
        throw new Error("Unsupported serialization type");
    }
  }

  /**
   * Restores a wallet from an encrypted serialization.
   *
   * This is an advanced alternative to calling `deserialize(serialization, password)` directly, which allows
   * you to offload the KDF execution to a non-UI thread (e.g. in a WebWorker).
   *
   * The caller is responsible for ensuring the key was derived with the given KDF configuration. This can be
   * done using `extractKdfConfiguration(serialization)` and `executeKdf(password, kdfConfiguration)` from this package.
   */
  public static async deserializeWithEncryptionKey(
    serialization: string,
    encryptionKey: Uint8Array,
  ): Promise<EthSecp256k1Wallet> {
    const root = JSON.parse(serialization);
    if (!isNonNullObject(root)) throw new Error("Root document is not an object.");
    const untypedRoot: any = root;
    switch (untypedRoot.type) {
      case serializationTypeV1: {
        const decryptedBytes = await decrypt(
          fromBase64(untypedRoot.data),
          encryptionKey,
          untypedRoot.encryption,
        );
        const decryptedDocument = JSON.parse(fromUtf8(decryptedBytes));
        const { mnemonic, accounts } = decryptedDocument;
        assert(typeof mnemonic === "string");
        if (!Array.isArray(accounts)) throw new Error("Property 'accounts' is not an array");
        if (accounts.length !== 1) throw new Error("Property 'accounts' only supports one entry");
        const account = accounts[0];
        if (!isSecp256k1DerivationJson(account)) throw new Error("Account is not in the correct format.");
        return EthSecp256k1Wallet.fromMnemonic(mnemonic, stringToPath(account.hdPath), account.prefix);
      }
      default:
        throw new Error("Unsupported serialization type");
    }
  }

  protected static async deserializeTypeV1(
    serialization: string,
    password: string,
  ): Promise<EthSecp256k1Wallet> {
    const root = JSON.parse(serialization);
    if (!isNonNullObject(root)) throw new Error("Root document is not an object.");
    const encryptionKey = await executeKdf(password, (root as any).kdf);
    return EthSecp256k1Wallet.deserializeWithEncryptionKey(serialization, encryptionKey);
  }

  protected get address(): string {
    return rawEthSecp256k1PubkeyToAddress(this.pubkey, this.accounts[0].prefix);
  }

  public async getAccounts(): Promise<readonly AccountData[]> {
    return [
      {
        algo: "eth_secp256k1",
        address: this.address,
        pubkey: this.pubkey,
      },
    ];
  }

  public async sign(signerAddress: string, signDoc: StdSignDoc): Promise<SignResponse> {
    if (signerAddress !== this.address) {
      throw new Error(`Address ${signerAddress} not found in wallet`);
    }
    const message = new Keccak256(serializeSignDoc(signDoc)).digest();
    const signature = await Secp256k1.createSignature(message, this.privkey);
    const signatureBytes = new Uint8Array([...signature.r(32), ...signature.s(32)]);
    return {
      signed: signDoc,
      signature: encodeEthSecp256k1Signature(this.pubkey, signatureBytes),
    };
  }
}
