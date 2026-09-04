import {
  defineRailway,
  github,
  preserve,
  project,
  service,
  volume,
} from "railway/iac";

export const partial = "sne-sec-celo-agent";

export default defineRailway(() => {
  const data = volume("sne-sec-celo agent-volume", {
    alerts: { usage: { "80": {}, "95": {}, "100": {} } },
    allowOnlineResize: true,
    region: "us-west2",
    sizeMB: 5000,
  });

  const agent = service("SNE-SEC Celo Agent", {
    source: github("SNE-Labs/SNE-SEC-Celo", {
      branch: "main",
      checkSuites: false,
    }),
    build: {
      buildEnvironment: "V3",
      builder: "DOCKERFILE",
      dockerfilePath: "Dockerfile",
    },
    deploy: {
      healthcheckPath: "/healthz",
      healthcheckTimeout: 120,
      ipv6EgressEnabled: false,
      multiRegionConfig: { "us-west2": { numReplicas: 1 } },
      runtime: "V2",
      useLegacyStacker: false,
    },
    networking: {
      privateNetworkEndpoint: "sne-sec-celo-agent",
      serviceDomains: {
        "sne-sec-celo-agent-production.up.railway.app": { port: 8000 },
      },
    },
    variables: {
      PORT: "8000",
      SNE_SEC_CELO_AGENT_WALLET: preserve(),
      SNE_SEC_CELO_ERC8004_AGENT_ID: preserve(),
      SNE_SEC_CELO_PUBLIC_EXAMPLE_REVIEW_ID:
        "review_ac8c7054897c4ec9ada5feae8dfcf8f3",
      SNE_SEC_CELO_PUBLIC_BASE_URL: preserve(),
      SNE_SEC_CELO_RPC_URL: "https://forno.celo.org",
      SNE_SEC_CELO_X402_AMOUNT_ATOMIC: "1000000",
      SNE_SEC_CELO_X402_API_KEY: preserve(),
      SNE_SEC_CELO_X402_ENABLED: preserve(),
      SNE_SEC_CELO_X402_FACILITATOR_URL: "https://api.x402.celo.org",
      SNE_SEC_CELO_X402_MIN_CONFIRMATIONS: "1",
      SNE_SEC_CELO_X402_PAY_TO: preserve(),
    },
    volumeMounts: {
      "/data": data,
    },
  });

  return project("SNE-SEC", { resources: [agent, data] });
});
