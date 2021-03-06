/* eslint-disable @typescript-eslint/naming-convention */
import { Bech32, toHex } from "@cosmjs/encoding";
import {
  Block,
  Coin,
  decodeAminoPubkey,
  isSearchByHeightQuery,
  isSearchByIdQuery,
  PubKey,
  SearchTxFilter,
  SearchTxQuery,
} from "@cosmjs/launchpad";
import { Uint53, Uint64 } from "@cosmjs/math";
import { broadcastTxCommitSuccess, Client as TendermintClient, QueryString } from "@cosmjs/tendermint-rpc";
import { assert, assertDefined } from "@cosmjs/utils";
import Long from "long";

import { cosmos } from "./codec";
import { AuthExtension, BankExtension, QueryClient, setupAuthExtension, setupBankExtension } from "./queries";

/** A transaction that is indexed as part of the transaction history */
export interface IndexedTx {
  readonly height: number;
  /** Transaction hash (might be used as transaction ID). Guaranteed to be non-empty upper-case hex */
  readonly hash: string;
  /** Transaction execution error code. 0 on success. */
  readonly code: number;
  readonly rawLog: string;
  readonly tx: Uint8Array;
}

export interface Account {
  /** Bech32 account address */
  readonly address: string;
  readonly pubkey: PubKey | null;
  readonly accountNumber: number;
  readonly sequence: number;
}

export interface SequenceResponse {
  readonly accountNumber: number;
  readonly sequence: number;
}

export interface BroadcastTxFailure {
  readonly height: number;
  readonly code: number;
  readonly transactionHash: string;
  readonly rawLog?: string;
  readonly data?: Uint8Array;
}

export interface BroadcastTxSuccess {
  readonly height: number;
  readonly transactionHash: string;
  readonly rawLog?: string;
  readonly data?: Uint8Array;
}

export type BroadcastTxResponse = BroadcastTxSuccess | BroadcastTxFailure;

export function isBroadcastTxFailure(result: BroadcastTxResponse): result is BroadcastTxFailure {
  return !!(result as BroadcastTxFailure).code;
}

export function isBroadcastTxSuccess(result: BroadcastTxResponse): result is BroadcastTxSuccess {
  return !isBroadcastTxFailure(result);
}

/**
 * Ensures the given result is a success. Throws a detailed error message otherwise.
 */
export function assertIsBroadcastTxSuccess(
  result: BroadcastTxResponse,
): asserts result is BroadcastTxSuccess {
  if (isBroadcastTxFailure(result)) {
    throw new Error(
      `Error when broadcasting tx ${result.transactionHash} at height ${result.height}. Code: ${result.code}; Raw log: ${result.rawLog}`,
    );
  }
}

function uint64FromProto(input: number | Long | null | undefined): Uint64 {
  if (!input) return Uint64.fromNumber(0);
  return Uint64.fromString(input.toString());
}

function accountFromProto(input: cosmos.auth.IBaseAccount, prefix: string): Account {
  const { address, pubKey, accountNumber, sequence } = input;
  // Pubkey is still Amino-encoded in BaseAccount (https://github.com/cosmos/cosmos-sdk/issues/6886)
  const pubkey = pubKey && pubKey.length ? decodeAminoPubkey(pubKey) : null;
  assert(address);
  return {
    address: Bech32.encode(prefix, address),
    pubkey: pubkey,
    accountNumber: uint64FromProto(accountNumber).toNumber(),
    sequence: uint64FromProto(sequence).toNumber(),
  };
}

function coinFromProto(input: cosmos.ICoin): Coin {
  assertDefined(input.amount);
  assertDefined(input.denom);
  assert(input.amount !== null);
  assert(input.denom !== null);
  return {
    amount: input.amount,
    denom: input.denom,
  };
}

/** Use for testing only */
export interface PrivateStargateClient {
  readonly tmClient: TendermintClient;
}

export class StargateClient {
  private readonly tmClient: TendermintClient;
  private readonly queryClient: QueryClient & AuthExtension & BankExtension;
  private chainId: string | undefined;

  public static async connect(endpoint: string): Promise<StargateClient> {
    const tmClient = await TendermintClient.connect(endpoint);
    return new StargateClient(tmClient);
  }

  private constructor(tmClient: TendermintClient) {
    this.tmClient = tmClient;
    this.queryClient = QueryClient.withExtensions(tmClient, setupAuthExtension, setupBankExtension);
  }

  public async getChainId(): Promise<string> {
    if (!this.chainId) {
      const response = await this.tmClient.status();
      const chainId = response.nodeInfo.network;
      if (!chainId) throw new Error("Chain ID must not be empty");
      this.chainId = chainId;
    }

    return this.chainId;
  }

  public async getHeight(): Promise<number> {
    const status = await this.tmClient.status();
    return status.syncInfo.latestBlockHeight;
  }

  public async getAccount(searchAddress: string): Promise<Account | null> {
    const { prefix } = Bech32.decode(searchAddress);

    const account = await this.queryClient.auth.account(searchAddress);
    return account ? accountFromProto(account, prefix) : null;
  }

  public async getSequence(address: string): Promise<SequenceResponse | null> {
    const account = await this.getAccount(address);
    if (account) {
      return {
        accountNumber: account.accountNumber,
        sequence: account.sequence,
      };
    } else {
      return null;
    }
  }

  public async getBlock(height?: number): Promise<Block> {
    const response = await this.tmClient.block(height);
    return {
      id: toHex(response.blockId.hash).toUpperCase(),
      header: {
        version: {
          block: new Uint53(response.block.header.version.block).toString(),
          app: new Uint53(response.block.header.version.app).toString(),
        },
        height: response.block.header.height,
        chainId: response.block.header.chainId,
        time: response.block.header.time.toISOString(),
      },
      txs: response.block.txs,
    };
  }

  public async getBalance(address: string, searchDenom: string): Promise<Coin | null> {
    const balance = await this.queryClient.bank.balance(address, searchDenom);
    return balance ? coinFromProto(balance) : null;
  }

  /**
   * Queries all balances for all denoms that belong to this address.
   *
   * Uses the grpc queries (which iterates over the store internally), and we cannot get
   * proofs from such a method.
   */
  public async getAllBalancesUnverified(address: string): Promise<readonly Coin[]> {
    const balances = await this.queryClient.bank.unverified.allBalances(address);
    return balances.map(coinFromProto);
  }

  public async searchTx(query: SearchTxQuery, filter: SearchTxFilter = {}): Promise<readonly IndexedTx[]> {
    const minHeight = filter.minHeight || 0;
    const maxHeight = filter.maxHeight || Number.MAX_SAFE_INTEGER;

    if (maxHeight < minHeight) return []; // optional optimization

    let txs: readonly IndexedTx[];

    if (isSearchByIdQuery(query)) {
      txs = await this.txsQuery(`tx.hash='${query.id}'`);
    } else if (isSearchByHeightQuery(query)) {
      txs =
        query.height >= minHeight && query.height <= maxHeight
          ? await this.txsQuery(`tx.height=${query.height}`)
          : [];
    } else {
      throw new Error("Unknown query type");
    }

    const filtered = txs.filter((tx) => tx.height >= minHeight && tx.height <= maxHeight);
    return filtered;
  }

  public disconnect(): void {
    this.tmClient.disconnect();
  }

  public async broadcastTx(tx: Uint8Array): Promise<BroadcastTxResponse> {
    const response = await this.tmClient.broadcastTxCommit({ tx });
    if (broadcastTxCommitSuccess(response)) {
      return {
        height: response.height,
        transactionHash: toHex(response.hash).toUpperCase(),
        rawLog: response.deliverTx?.log,
        data: response.deliverTx?.data,
      };
    }
    return response.checkTx.code !== 0
      ? {
          height: response.height,
          code: response.checkTx.code,
          transactionHash: toHex(response.hash).toUpperCase(),
          rawLog: response.checkTx.log,
          data: response.checkTx.data,
        }
      : {
          height: response.height,
          code: response.deliverTx?.code,
          transactionHash: toHex(response.hash).toUpperCase(),
          rawLog: response.deliverTx?.log,
          data: response.deliverTx?.data,
        };
  }

  private async txsQuery(query: string): Promise<readonly IndexedTx[]> {
    const params = {
      query: query as QueryString,
    };
    const results = await this.tmClient.txSearchAll(params);
    return results.txs.map((tx) => {
      return {
        height: tx.height,
        hash: toHex(tx.hash).toUpperCase(),
        code: tx.result.code,
        rawLog: tx.result.log || "",
        tx: tx.tx,
      };
    });
  }
}
