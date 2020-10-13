/* eslint-disable @typescript-eslint/naming-convention */
import { Keccak256, Secp256k1, Secp256k1Signature } from "@cosmjs/crypto";
import { fromBase64, fromHex } from "@cosmjs/encoding";

import { serializeSignDoc, StdSignDoc } from "./encoding";
import { EthSecp256k1Wallet } from "./ethsecp256k1wallet";
import { extractKdfConfiguration } from "./secp256k1wallet";
import { base64Matcher } from "./testutils.spec";
import { executeKdf, KdfConfiguration } from "./wallet";

describe("EthSecp256k1Wallet", () => {
  // m/44'/60'/0'/0/0
  // pubkey: 03d1d258e68d8b21ddfdd399762325984a27f10836f83ae56f8c2188143125129d
  const defaultMnemonic =
    "rather ill seminar earth dust increase network before raccoon clerk issue hazard plunge account will fatigue clump service window grape duty attitude beauty feel";
  const defaultPubkey = fromHex("03d1d258e68d8b21ddfdd399762325984a27f10836f83ae56f8c2188143125129d"); // @FIXME
  const defaultAddress = "eth1wx4tedkw2nd50hykv6vym0k2uxavuvd65l7pe5";

  describe("fromMnemonic", () => {
    it("works", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
      expect(wallet).toBeTruthy();
      expect(wallet.mnemonic).toEqual(defaultMnemonic);
    });
  });

  describe("generate", () => {
    it("defaults to 12 words", async () => {
      const wallet = await EthSecp256k1Wallet.generate();
      expect(wallet.mnemonic.split(" ").length).toEqual(12);
    });

    it("can use different mnemonic lengths", async () => {
      expect((await EthSecp256k1Wallet.generate(12)).mnemonic.split(" ").length).toEqual(12);
      expect((await EthSecp256k1Wallet.generate(15)).mnemonic.split(" ").length).toEqual(15);
      expect((await EthSecp256k1Wallet.generate(18)).mnemonic.split(" ").length).toEqual(18);
      expect((await EthSecp256k1Wallet.generate(21)).mnemonic.split(" ").length).toEqual(21);
      expect((await EthSecp256k1Wallet.generate(24)).mnemonic.split(" ").length).toEqual(24);
    });
  });

  describe("deserialize", () => {
    it("can restore", async () => {
      const original = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
      const password = "123";
      const serialized = await original.serialize(password);
      const deserialized = await EthSecp256k1Wallet.deserialize(serialized, password);
      expect(deserialized.mnemonic).toEqual(defaultMnemonic);
      expect(await deserialized.getAccounts()).toEqual([
        {
          algo: "eth_secp256k1",
          address: defaultAddress,
          pubkey: defaultPubkey,
        },
      ]);
    });
  });

  describe("deserializeWithEncryptionKey", () => {
    it("can restore", async () => {
      const password = "123";
      let serialized: string;
      {
        const original = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
        const anyKdfParams: KdfConfiguration = {
          algorithm: "argon2id",
          params: {
            outputLength: 32,
            opsLimit: 4,
            memLimitKib: 3 * 1024,
          },
        };
        const encryptionKey = await executeKdf(password, anyKdfParams);
        serialized = await original.serializeWithEncryptionKey(encryptionKey, anyKdfParams);
      }

      {
        const kdfConfiguration = extractKdfConfiguration(serialized);
        const encryptionKey = await executeKdf(password, kdfConfiguration);
        const deserialized = await EthSecp256k1Wallet.deserializeWithEncryptionKey(serialized, encryptionKey);
        expect(deserialized.mnemonic).toEqual(defaultMnemonic);
        expect(await deserialized.getAccounts()).toEqual([
          {
            algo: "eth_secp256k1",
            address: defaultAddress,
            pubkey: defaultPubkey,
          },
        ]);
      }
    });
  });

  describe("getAccounts", () => {
    it("resolves to a list of accounts", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
      const accounts = await wallet.getAccounts();
      expect(accounts.length).toEqual(1);
      expect(accounts[0]).toEqual({
        algo: "eth_secp256k1",
        address: defaultAddress,
        pubkey: defaultPubkey,
      });
    });

    it("creates the same address as Go implementation", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(
        "oyster design unusual machine spread century engine gravity focus cave carry slot",
      );
      const [{ address }] = await wallet.getAccounts();
      expect(address).toEqual("eth1cjsxept9rkggzxztslae9ndgpdyt2408lk850u");
    });
  });

  describe("sign", () => {
    it("resolves to valid signature if enabled", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
      const signDoc: StdSignDoc = {
        msgs: [],
        fee: { amount: [], gas: "23" },
        chain_id: "foochain",
        memo: "hello, world",
        account_number: "7",
        sequence: "54",
      };
      const { signed, signature } = await wallet.sign(defaultAddress, signDoc);
      expect(signed).toEqual(signDoc);
      const valid = await Secp256k1.verifySignature(
        Secp256k1Signature.fromFixedLength(fromBase64(signature.signature)),
        new Keccak256(serializeSignDoc(signed)).digest(),
        defaultPubkey,
      );
      expect(valid).toEqual(true);
    });
  });

  describe("serialize", () => {
    it("can save with password", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);
      const serialized = await wallet.serialize("123");
      expect(JSON.parse(serialized)).toEqual({
        type: "secp256k1wallet-v1",
        kdf: {
          algorithm: "argon2id",
          params: {
            outputLength: 32,
            opsLimit: 20,
            memLimitKib: 12 * 1024,
          },
        },
        encryption: {
          algorithm: "xchacha20poly1305-ietf",
        },
        data: jasmine.stringMatching(base64Matcher),
      });
    });
  });

  describe("serializeWithEncryptionKey", () => {
    it("can save with password", async () => {
      const wallet = await EthSecp256k1Wallet.fromMnemonic(defaultMnemonic);

      const key = fromHex("aabb221100aabb332211aabb33221100aabb221100aabb332211aabb33221100");
      const customKdfConfiguration: KdfConfiguration = {
        algorithm: "argon2id",
        params: {
          outputLength: 32,
          opsLimit: 321,
          memLimitKib: 11 * 1024,
        },
      };
      const serialized = await wallet.serializeWithEncryptionKey(key, customKdfConfiguration);
      expect(JSON.parse(serialized)).toEqual({
        type: "secp256k1wallet-v1",
        kdf: customKdfConfiguration,
        encryption: {
          algorithm: "xchacha20poly1305-ietf",
        },
        data: jasmine.stringMatching(base64Matcher),
      });
    });
  });
});
