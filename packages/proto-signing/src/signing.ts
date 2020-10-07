/* eslint-disable @typescript-eslint/naming-convention */
import Long from "long";

import { omitDefaults } from "./adr27";
import { cosmos, google } from "./codec";

const { SignDoc, AuthInfo } = cosmos.tx.v1beta1;

/**
 * Creates and serializes an AuthInfo document using SIGN_MODE_DIRECT.
 */
export function makeAuthInfo(pubkeys: readonly google.protobuf.IAny[], gasLimit: number): Uint8Array {
  const authInfo = {
    signerInfos: pubkeys.map(
      (pubkey): cosmos.tx.v1beta1.ISignerInfo => ({
        publicKey: pubkey,
        modeInfo: {
          single: { mode: cosmos.tx.signing.v1beta1.SignMode.SIGN_MODE_DIRECT },
        },
      }),
    ),
    fee: { gasLimit: Long.fromNumber(gasLimit) },
  };
  return Uint8Array.from(AuthInfo.encode(authInfo).finish());
}

export function makeSignBytes(
  txBody: Uint8Array,
  authInfo: Uint8Array,
  chainId: string,
  accountNumber: number,
  sequence: number,
): Uint8Array {
  const signDoc = SignDoc.create(
    omitDefaults({
      bodyBytes: txBody,
      authInfoBytes: authInfo,
      chainId: chainId,
      accountNumber: accountNumber,
      accountSequence: sequence,
    }),
  );
  return Uint8Array.from(SignDoc.encode(signDoc).finish());
}
