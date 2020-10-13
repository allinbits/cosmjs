import { Random } from "@cosmjs/crypto";
import { Bech32 } from "@cosmjs/encoding";
import { CosmosClient } from "@cosmjs/launchpad";
import { assert } from "@cosmjs/utils";

import { Faucet } from "./faucet";
import { TokenConfiguration } from "./tokenmanager";

function pendingWithoutWasmd(): void {
  if (!process.env.WASMD_ENABLED) {
    return pending("Set WASMD_ENABLED to enable Cosmos node-based tests");
  }
}

const httpUrl = "http://localhost:1317";
const defaultTokenConfig: TokenConfiguration = {
  bankTokens: ["ueth", "ustake"],
};
const defaultAddressPrefix = "eth";

function makeRandomAddress(): string {
  return Bech32.encode(defaultAddressPrefix, Random.getBytes(20));
}

const faucetMnemonic =
  "economy stock theory fatal elder harbor betray wasp final emotion task crumble siren bottom lizard educate guess current outdoor pair theory focus wife stone";

describe("Faucet", () => {
  describe("constructor", () => {
    it("can be constructed", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      expect(faucet).toBeTruthy();
    });
  });

  describe("availableTokens", () => {
    it("is empty when no tokens are configured", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, { bankTokens: [] }, faucetMnemonic, 3);
      const tickers = await faucet.availableTokens();
      expect(tickers).toEqual([]);
    });

    it("is not empty with default token config", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      const tickers = await faucet.availableTokens();
      expect(tickers).toEqual(["ueth", "ustake"]);
    });
  });

  describe("send", () => {
    it("can send bank token", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      const recipient = makeRandomAddress();
      await faucet.send({
        amount: {
          amount: "23456",
          denom: "ueth",
        },
        sender: faucet.holderAddress,
        recipient: recipient,
      });

      const readOnlyClient = new CosmosClient(httpUrl);
      const account = await readOnlyClient.getAccount(recipient);
      assert(account);
      expect(account.balance).toEqual([
        {
          amount: "23456",
          denom: "ueth",
        },
      ]);
    });
  });

  describe("refill", () => {
    it("works", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      await faucet.refill();
      const readOnlyClient = new CosmosClient(httpUrl);
      const distributorBalance = (await readOnlyClient.getAccount(faucet.distributorAddresses[0]))?.balance;
      assert(distributorBalance);
      expect(distributorBalance).toEqual([
        jasmine.objectContaining({
          denom: "ueth",
        }),
        jasmine.objectContaining({
          denom: "ustake",
        }),
      ]);
      expect(Number.parseInt(distributorBalance[0].amount, 10)).toBeGreaterThanOrEqual(80_000000);
      expect(Number.parseInt(distributorBalance[1].amount, 10)).toBeGreaterThanOrEqual(80_000000);
    });
  });

  describe("credit", () => {
    it("works for fee token", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      const recipient = makeRandomAddress();
      await faucet.credit(recipient, "ueth");

      const readOnlyClient = new CosmosClient(httpUrl);
      const account = await readOnlyClient.getAccount(recipient);
      assert(account);
      expect(account.balance).toEqual([
        {
          amount: "10000000",
          denom: "ueth",
        },
      ]);
    });

    it("works for stake token", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      const recipient = makeRandomAddress();
      await faucet.credit(recipient, "ustake");

      const readOnlyClient = new CosmosClient(httpUrl);
      const account = await readOnlyClient.getAccount(recipient);
      assert(account);
      expect(account.balance).toEqual([
        {
          amount: "10000000",
          denom: "ustake",
        },
      ]);
    });
  });

  describe("configuredTokens", () => {
    it("works", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 3);
      const tickers = faucet.configuredTokens();
      expect(tickers).toEqual(["ueth", "ustake"]);
    });
  });

  describe("loadAccounts", () => {
    it("works", async () => {
      pendingWithoutWasmd();
      const faucet = await Faucet.make(httpUrl, defaultAddressPrefix, defaultTokenConfig, faucetMnemonic, 1);
      const accounts = await faucet.loadAccounts();

      const readOnlyClient = new CosmosClient(httpUrl);
      const expectedHolderAccount = await readOnlyClient.getAccount(faucet.holderAddress);
      const expectedDistributorAccount = await readOnlyClient.getAccount(faucet.distributorAddresses[0]);
      assert(expectedHolderAccount);
      assert(expectedDistributorAccount);
      expect(accounts).toEqual([
        jasmine.objectContaining({
          address: expectedHolderAccount.address,
          balance: expectedHolderAccount.balance,
        }),
        jasmine.objectContaining({
          address: expectedDistributorAccount.address,
          balance: expectedDistributorAccount.balance,
        }),
      ]);
    });
  });
});
