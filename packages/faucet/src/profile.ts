import { pathToString } from "@cosmjs/crypto";
import { makeEthermintPath, OfflineSigner, EthSecp256k1Wallet } from "@cosmjs/launchpad";

export async function createWallets(
  mnemonic: string,
  addressPrefix: string,
  numberOfDistributors: number,
  logging = false,
): Promise<ReadonlyArray<readonly [string, OfflineSigner]>> {
  const wallets = new Array<readonly [string, OfflineSigner]>();

  // first account is the token holder
  const numberOfIdentities = 1 + numberOfDistributors;
  for (let i = 0; i < numberOfIdentities; i++) {
    const path = makeEthermintPath(i);
    const wallet = await EthSecp256k1Wallet.fromMnemonic(mnemonic, path, addressPrefix);
    const [{ address }] = await wallet.getAccounts();
    if (logging) {
      const role = i === 0 ? "token holder " : `distributor ${i}`;
      console.info(`Created ${role} (${pathToString(path)}): ${address}`);
    }
    wallets.push([address, wallet]);
  }

  return wallets;
}
