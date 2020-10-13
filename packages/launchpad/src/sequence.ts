import { Keccak256, Secp256k1, Secp256k1Signature, Sha256 } from "@cosmjs/crypto";

import { makeSignDoc, serializeSignDoc } from "./encoding";
import { decodeSignature } from "./signature";
import { WrappedStdTx } from "./tx";
import { pubkeyType } from "./types";

/**
 * Serach for sequence s with `min` <= `s` < `upperBound` to find the sequence that was used to sign the transaction
 *
 * @param tx The signed transaction
 * @param chainId The chain ID for which this transaction was signed
 * @param accountNumber The account number for which this transaction was signed
 * @param upperBound The upper bound for the testing, i.e. sequence must be lower than this value
 * @param min The lowest sequence that is tested
 *
 * @returns the sequence if a match was found and undefined otherwise
 */
export async function findSequenceForSignedTx(
  tx: WrappedStdTx,
  chainId: string,
  accountNumber: number,
  upperBound: number,
  min = 0,
): Promise<number | undefined> {
  const firstSignature = tx.value.signatures.find(() => true);
  if (!firstSignature) throw new Error("Signature missing in tx");

  const { pubkey, signature } = decodeSignature(firstSignature);
  const secp256k1Signature = Secp256k1Signature.fromFixedLength(signature);

  switch (firstSignature.pub_key.type) {
    case pubkeyType.eth_secp256k1:
      for (let s = min; s < upperBound; s++) {
        // console.log(`Trying sequence ${s}`);
        const signBytes = serializeSignDoc(
          makeSignDoc(tx.value.msg, tx.value.fee, chainId, tx.value.memo || "", accountNumber, s),
        );
        const prehashed = new Keccak256(signBytes).digest();
        const valid = await Secp256k1.verifySignature(secp256k1Signature, prehashed, pubkey);
        if (valid) return s;
      }
      break;
    case pubkeyType.secp256k1:
      for (let s = min; s < upperBound; s++) {
        // console.log(`Trying sequence ${s}`);
        const signBytes = serializeSignDoc(
          makeSignDoc(tx.value.msg, tx.value.fee, chainId, tx.value.memo || "", accountNumber, s),
        );
        const prehashed = new Sha256(signBytes).digest();
        const valid = await Secp256k1.verifySignature(secp256k1Signature, prehashed, pubkey);
        if (valid) return s;
      }
      break;
    default:
      break;
  }

  return undefined;
}
