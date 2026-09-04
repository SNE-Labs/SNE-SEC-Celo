import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import type { ClientEvmSigner } from "@x402/evm";
import type { FullReview } from "./api";

export class WalletUnavailableError extends Error {}

export async function unlockReview(reviewId: string): Promise<FullReview> {
  const provider = window.ethereum;
  if (!provider) {
    throw new WalletUnavailableError(
      "No EVM wallet detected. Open in MiniPay or install an EVM wallet.",
    );
  }

  const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
  const account = accounts[0];
  if (!account || !/^0x[0-9a-fA-F]{40}$/.test(account)) {
    throw new WalletUnavailableError("The wallet did not expose an account.");
  }

  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0xa4ec" }],
    });
  } catch {
    // MiniPay is Celo-native and some injected providers do not expose chain switching.
    const currentChain = await provider.request({ method: "eth_chainId" });
    if (String(currentChain).toLowerCase() !== "0xa4ec") {
      throw new WalletUnavailableError("Connect the wallet to Celo Mainnet and try again.");
    }
  }

  const signer: ClientEvmSigner = {
    address: account as `0x${string}`,
    async signTypedData(message) {
      const signature = await provider.request({
        method: "eth_signTypedData_v4",
        params: [account, JSON.stringify(message)],
      });
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
        throw new WalletUnavailableError("The wallet returned a malformed signature.");
      }
      return signature as `0x${string}`;
    },
  };
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);
  const response = await fetchWithPayment(`/v1/x402/reviews/${encodeURIComponent(reviewId)}`);
  if (!response.ok) {
    throw new Error(`Paid delivery failed with status ${response.status}.`);
  }
  return (await response.json()) as FullReview;
}
