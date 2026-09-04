export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ReviewPreview {
  review_id: string;
  status: "COMPLETED";
  score: number;
  summary: {
    finding_count: number;
    highest_severity: Severity | null;
    severity_counts: Record<Severity, number>;
  };
}

export interface CommercialOffer {
  network: string;
  asset: string;
  asset_symbol: string;
  asset_decimals: number;
  amount_atomic: string;
  available: boolean;
  method: "GET";
  route_template: string;
}

export interface CommercialPolicy {
  schema_version: string;
  x402: {
    full_review: CommercialOffer;
    full_review_diff: CommercialOffer;
  };
  billing_policy: string;
}

export interface FullReview extends Record<string, unknown> {
  review_id: string;
  target_origin: string;
  score: number;
  findings: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  evaluations: Array<Record<string, unknown>>;
  result_digest: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function expectJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string; error?: string };
      message = body.detail ?? body.error ?? message;
    } catch {
      // The status remains the authoritative error when no JSON body exists.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export async function createReview(target: string, signal?: AbortSignal): Promise<ReviewPreview> {
  return expectJson<ReviewPreview>(
    await fetch("/v1/reference/reviews", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
      signal,
    }),
  );
}

export async function getCommercialPolicy(signal?: AbortSignal): Promise<CommercialPolicy> {
  return expectJson<CommercialPolicy>(
    await fetch("/.well-known/sne-sec-commerce.json", { signal }),
  );
}
