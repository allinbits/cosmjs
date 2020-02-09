/* eslint-disable @typescript-eslint/camelcase */
import { encodeSecp256k1Signature, types } from "@cosmwasm/sdk";
import {
  Algorithm,
  Amount,
  Fee,
  FullSignature,
  isSendTransaction,
  PubkeyBundle,
  SignedTransaction,
  UnsignedTransaction,
} from "@iov/bcp";
import { Decimal, Encoding } from "@iov/encoding";

import { BankTokens } from "./types";

const { toBase64 } = Encoding;

export function encodePubkey(pubkey: PubkeyBundle): types.PubKey {
  switch (pubkey.algo) {
    case Algorithm.Secp256k1:
      return {
        type: types.pubkeyType.secp256k1,
        value: toBase64(pubkey.data),
      };
    case Algorithm.Ed25519:
      return {
        type: types.pubkeyType.ed25519,
        value: toBase64(pubkey.data),
      };
    default:
      throw new Error("Unsupported pubkey algo");
  }
}

export function decimalToCoin(lookup: BankTokens, value: Decimal, ticker: string): types.Coin {
  const match = lookup.find(token => token.ticker === ticker);
  if (!match) {
    throw Error(`unknown ticker: ${ticker}`);
  }
  if (match.fractionalDigits !== value.fractionalDigits) {
    throw new Error(
      "Mismatch in fractional digits between token and value. If you really want, implement a conversion here. However, this indicates a bug in the caller code.",
    );
  }
  return {
    denom: match.denom,
    amount: value.atomics,
  };
}

export function encodeAmount(amount: Amount, tokens: BankTokens): types.Coin {
  return decimalToCoin(
    tokens,
    Decimal.fromAtomics(amount.quantity, amount.fractionalDigits),
    amount.tokenTicker,
  );
}

export function encodeFee(fee: Fee, tokens: BankTokens): types.StdFee {
  if (fee.tokens === undefined) {
    throw new Error("Cannot encode fee without tokens");
  }
  if (fee.gasLimit === undefined) {
    throw new Error("Cannot encode fee without gas limit");
  }
  return {
    amount: [encodeAmount(fee.tokens, tokens)],
    gas: fee.gasLimit,
  };
}

export function encodeFullSignature(fullSignature: FullSignature): types.StdSignature {
  switch (fullSignature.pubkey.algo) {
    case Algorithm.Secp256k1:
      return encodeSecp256k1Signature(fullSignature.pubkey.data, fullSignature.signature);
    default:
      throw new Error("Unsupported signing algorithm");
  }
}

export function buildUnsignedTx(tx: UnsignedTransaction, tokens: BankTokens): types.AminoTx {
  if (!isSendTransaction(tx)) {
    throw new Error("Received transaction of unsupported kind");
  }
  return {
    type: "cosmos-sdk/StdTx",
    value: {
      msg: [
        {
          type: "cosmos-sdk/MsgSend",
          value: {
            from_address: tx.sender,
            to_address: tx.recipient,
            amount: [encodeAmount(tx.amount, tokens)],
          },
        },
      ],
      memo: tx.memo || "",
      signatures: [],
      fee: tx.fee
        ? encodeFee(tx.fee, tokens)
        : {
            amount: [],
            gas: "",
          },
    },
  };
}

export function buildSignedTx(tx: SignedTransaction, tokens: BankTokens): types.AminoTx {
  const built = buildUnsignedTx(tx.transaction, tokens);
  return {
    ...built,
    value: {
      ...built.value,
      signatures: tx.signatures.map(encodeFullSignature),
    },
  };
}
