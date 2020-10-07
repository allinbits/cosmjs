/* eslint-disable @typescript-eslint/naming-convention */
import { fromBase64 } from "@cosmjs/encoding";
import { Client as TendermintClient } from "@cosmjs/tendermint-rpc";
import { assert } from "@cosmjs/utils";
import Long from "long";

import { google } from "../codec";
import { nonExistentAddress, pendingWithoutSimapp, simapp, unused, validator } from "../testutils.spec";
import { AuthExtension, setupAuthExtension } from "./auth";
import { QueryClient } from "./queryclient";

const { Any } = google.protobuf;

async function makeClientWithAuth(rpcUrl: string): Promise<[QueryClient & AuthExtension, TendermintClient]> {
  const tmClient = await TendermintClient.connect(rpcUrl);
  return [QueryClient.withExtensions(tmClient, setupAuthExtension), tmClient];
}

describe("AuthExtension", () => {
  describe("account", () => {
    it("works for unused account", async () => {
      pendingWithoutSimapp();
      const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

      const account = await client.auth.account(unused.address);
      assert(account);

      expect(account).toEqual({
        address: unused.address,
        // pubKey not set
        accountNumber: Long.fromNumber(unused.accountNumber, true),
        // sequence not set
      });

      tmClient.disconnect();
    });

    it("works for account with pubkey and non-zero sequence", async () => {
      pendingWithoutSimapp();
      const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

      const account = await client.auth.account(validator.address);
      assert(account);
      // TODO: Sort out pubkey encoding
      const publicKeyAny = Any.create({
        type_url: "/cosmos.crypto.secp256k1.PubKey",
        value: Uint8Array.from([0x0a, 0x21, ...fromBase64(validator.pubkey.value)]),
      });
      expect(account).toEqual({
        address: validator.address,
        pubKey: publicKeyAny,
        // accountNumber not set
        sequence: Long.fromNumber(validator.sequence, true),
      });

      tmClient.disconnect();
    });

    it("returns null for non-existent address", async () => {
      pendingWithoutSimapp();
      const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

      const account = await client.auth.account(nonExistentAddress);
      expect(account).toBeNull();

      tmClient.disconnect();
    });
  });

  describe("unverified", () => {
    describe("account", () => {
      it("works for unused account", async () => {
        pendingWithoutSimapp();
        const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

        const account = await client.auth.unverified.account(unused.address);
        assert(account);
        expect(account).toEqual({
          address: unused.address,
          // pubKey not set
          accountNumber: Long.fromNumber(unused.accountNumber, true),
          // sequence not set
        });

        tmClient.disconnect();
      });

      it("works for account with pubkey and non-zero sequence", async () => {
        pendingWithoutSimapp();
        const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

        const account = await client.auth.unverified.account(validator.address);
        const publicKeyAny = Any.create({
          type_url: "/cosmos.crypto.secp256k1.PubKey",
          value: Uint8Array.from([...[0x0a, 0x21], ...fromBase64(validator.pubkey.value)]),
        });
        assert(account);
        expect(account).toEqual({
          address: validator.address,
          pubKey: publicKeyAny,
          // accountNumber not set
          sequence: Long.fromNumber(validator.sequence, true),
        });

        tmClient.disconnect();
      });

      it("returns null for non-existent address", async () => {
        pendingWithoutSimapp();
        const [client, tmClient] = await makeClientWithAuth(simapp.tendermintUrl);

        await expectAsync(client.auth.unverified.account(nonExistentAddress)).toBeRejectedWithError(
          /account cosmos(.+) not found/i,
        );

        tmClient.disconnect();
      });
    });
  });
});
