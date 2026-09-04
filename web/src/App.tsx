import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  createReview,
  getCommercialPolicy,
  type CommercialPolicy,
  type FullReview,
  type ReviewPreview,
  type Severity,
} from "./api";

type Phase = "IDLE" | "ANALYZING" | "PREVIEW" | "UNLOCKING" | "UNLOCKED" | "ERROR";

interface IntelEvent {
  at: string;
  label: string;
  detail: string;
  tone: "neutral" | "admitted" | "attention";
}

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function timestamp(): string {
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());
}

function displayOrigin(value: string): string {
  const trimmed = value.trim();
  try {
    return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`).hostname.toUpperCase();
  } catch {
    return trimmed.toUpperCase();
  }
}

function shortId(value: string): string {
  if (value.length <= 22) return value.toUpperCase();
  return `${value.slice(0, 15)}…${value.slice(-6)}`.toUpperCase();
}

function formatPrice(policy: CommercialPolicy | null): string {
  const offer = policy?.x402.full_review;
  if (!offer) return "—";
  const amount = BigInt(offer.amount_atomic);
  const base = 10n ** BigInt(offer.asset_decimals);
  const whole = amount / base;
  const fraction = (amount % base).toString().padStart(offer.asset_decimals, "0").replace(/0+$/, "");
  return `${whole}${fraction ? `.${fraction}` : ""} ${offer.asset_symbol}`;
}

function AmbientGraph({ phase, origin, preview }: { phase: Phase; origin: string; preview: ReviewPreview | null }) {
  return (
    <svg className="intel-graph" viewBox="0 0 920 600" role="img" aria-label="Review intelligence relationship map">
      <defs>
        <radialGradient id="field" cx="50%" cy="48%" r="48%">
          <stop offset="0" stopColor="#8cad74" stopOpacity="0.065" />
          <stop offset="1" stopColor="#8cad74" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx="460" cy="292" r="260" fill="url(#field)" />
      <g className="graph-ghost">
        <path d="M44 112 210 172 326 82 460 292 630 126 876 190" />
        <path d="M74 454 238 386 460 292 666 414 858 494" />
        <path d="M210 172 238 386M630 126 666 414" />
        <circle cx="44" cy="112" r="3" /><circle cx="74" cy="454" r="3" />
        <circle cx="876" cy="190" r="3" /><circle cx="858" cy="494" r="3" />
      </g>
      <g className={phase === "ANALYZING" ? "graph-live scanning" : "graph-live"}>
        <path d="M256 160 382 244M256 414 382 340M538 244 664 160M538 340 664 414" />
        <circle cx="256" cy="160" r="5" /><circle cx="256" cy="414" r="5" />
        <circle cx="664" cy="160" r="5" /><circle cx="664" cy="414" r="5" />
      </g>
      <g className="source-node" transform="translate(186 126)">
        <path d="M0 12 12 0h128l12 12v54l-12 12H12L0 66Z" />
        <text x="16" y="29">REQUEST</text>
        <text className="node-sub" x="16" y="51">{phase === "IDLE" ? "STANDBY" : "DISPATCHED"}</text>
      </g>
      <g className="source-node" transform="translate(186 380)">
        <path d="M0 12 12 0h128l12 12v54l-12 12H12L0 66Z" />
        <text x="16" y="29">REVIEW</text>
        <text className="node-sub" x="16" y="51">{preview ? "IMMUTABLE" : "PENDING"}</text>
      </g>
      <g className="source-node" transform="translate(582 126)">
        <path d="M0 12 12 0h128l12 12v54l-12 12H12L0 66Z" />
        <text x="16" y="29">PROJECTION</text>
        <text className="node-sub" x="16" y="51">{preview ? "PUBLIC / SAFE" : "AWAITING"}</text>
      </g>
      <g className="source-node" transform="translate(582 380)">
        <path d="M0 12 12 0h128l12 12v54l-12 12H12L0 66Z" />
        <text x="16" y="29">FULL INTEL</text>
        <text className="node-sub" x="16" y="51">{phase === "UNLOCKED" ? "DELIVERED" : "CONTROLLED"}</text>
      </g>
      <g className="identity-node" transform="translate(318 220)">
        <path d="M0 18 18 0h248l18 18v126l-18 18H18L0 144Z" />
        <text className="identity-kicker" x="142" y="34" textAnchor="middle">
          {phase === "IDLE" ? "AWAITING ORIGIN" : phase === "ANALYZING" ? "OBSERVATION ACTIVE" : "POSTURE OBSERVED"}
        </text>
        <text className="identity-origin" x="142" y="82" textAnchor="middle">{origin || "—"}</text>
        <text className="identity-score" x="142" y="128" textAnchor="middle">
          {preview ? `${preview.score} / 100` : phase === "ANALYZING" ? "PENDING" : "NO REVIEW"}
        </text>
      </g>
    </svg>
  );
}

function IntelTimeline({ events, elapsed }: { events: IntelEvent[]; elapsed: number }) {
  return (
    <section className="timeline" aria-label="Operation chronology">
      <div className="section-label">OPERATION CHRONOLOGY <span>// CLIENT LOCAL</span></div>
      <div className="timeline-track">
        {events.map((event, index) => (
          <div className={`timeline-event ${event.tone}`} key={`${event.at}-${event.label}`}>
            <span className="event-dot" />
            <time>{event.at}</time>
            <strong>{event.label}</strong>
            <small>{event.detail}</small>
          </div>
        ))}
        {events.length === 0 && <div className="timeline-empty">NO OPERATIONAL EVENTS</div>}
        {elapsed > 0 && <div className="elapsed">T+{elapsed.toString().padStart(3, "0")}s</div>}
      </div>
    </section>
  );
}

function PublicBrief({ preview }: { preview: ReviewPreview | null }) {
  return (
    <aside className="brief" aria-label="Public intelligence brief">
      <div className="brief-heading"><span>PUBLIC INTELLIGENCE BRIEF</span><i /></div>
      {!preview ? (
        <div className="brief-empty">
          <strong>NO ADMITTED REVIEW</strong>
          <p>Submit a public origin to establish an evidence-backed posture.</p>
        </div>
      ) : (
        <>
          <div className="brief-meta">
            <span>STATUS</span><strong>{preview.status}</strong>
            <span>REVIEW</span><strong title={preview.review_id}>{shortId(preview.review_id)}</strong>
          </div>
          <div className="severity-list">
            {severityOrder.map((severity) => (
              <div className={`severity severity-${severity.toLowerCase()}`} key={severity}>
                <i aria-hidden="true" /><strong>{preview.summary.severity_counts[severity]}</strong><span>{severity}</span>
              </div>
            ))}
          </div>
          <div className="finding-total">
            <span>AGGREGATE SIGNALS</span>
            <strong>{preview.summary.finding_count} FINDINGS</strong>
          </div>
          <p className="boundary-note">Evidence, rule evaluations, finding narratives and remediation are absent from this public response.</p>
        </>
      )}
    </aside>
  );
}

export default function App() {
  const [target, setTarget] = useState("");
  const [submittedTarget, setSubmittedTarget] = useState("");
  const [phase, setPhase] = useState<Phase>("IDLE");
  const [preview, setPreview] = useState<ReviewPreview | null>(null);
  const [fullReview, setFullReview] = useState<FullReview | null>(null);
  const [policy, setPolicy] = useState<CommercialPolicy | null>(null);
  const [events, setEvents] = useState<IntelEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    const abort = new AbortController();
    getCommercialPolicy(abort.signal).then(setPolicy).catch(() => setPolicy(null));
    return () => abort.abort();
  }, []);

  useEffect(() => {
    if (phase !== "ANALYZING") return;
    const started = Date.now();
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [phase]);

  const origin = useMemo(() => displayOrigin(submittedTarget || target), [submittedTarget, target]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const cleanTarget = target.trim();
    if (!cleanTarget || phase === "ANALYZING" || phase === "UNLOCKING") return;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setSubmittedTarget(cleanTarget);
    setPreview(null);
    setFullReview(null);
    setError(null);
    setElapsed(0);
    setPhase("ANALYZING");
    setEvents([{ at: timestamp(), label: "REQUEST DISPATCHED", detail: "Awaiting server admission and completion", tone: "neutral" }]);
    try {
      const result = await createReview(cleanTarget, abort.signal);
      setPreview(result);
      setPhase("PREVIEW");
      setEvents((current) => [
        ...current,
        { at: timestamp(), label: "REVIEW COMPLETED", detail: shortId(result.review_id), tone: "admitted" },
        { at: timestamp(), label: "PUBLIC PROJECTION RECEIVED", detail: "Aggregate posture only", tone: "admitted" },
      ]);
    } catch (caught) {
      if (abort.signal.aborted) return;
      const message = caught instanceof ApiError ? caught.message : "The assessment could not be completed.";
      setError(message);
      setPhase("ERROR");
      setEvents((current) => [...current, { at: timestamp(), label: "ASSESSMENT NOT ADMITTED", detail: message, tone: "attention" }]);
    }
  }

  async function unlock() {
    if (!preview || phase === "UNLOCKING") return;
    setError(null);
    setPhase("UNLOCKING");
    setEvents((current) => [...current, { at: timestamp(), label: "WALLET AUTHORIZATION REQUESTED", detail: "No transaction has been admitted yet", tone: "neutral" }]);
    try {
      const { unlockReview } = await import("./payment");
      const review = await unlockReview(preview.review_id);
      setFullReview(review);
      setPhase("UNLOCKED");
      setEvents((current) => [...current, { at: timestamp(), label: "SETTLEMENT ADMITTED", detail: "Full Review delivered", tone: "admitted" }]);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Payment could not be completed.";
      setError(message);
      setPhase("PREVIEW");
      setEvents((current) => [...current, { at: timestamp(), label: "ACCESS NOT GRANTED", detail: message, tone: "attention" }]);
    }
  }

  const offer = policy?.x402.full_review;
  const busy = phase === "ANALYZING" || phase === "UNLOCKING";

  return (
    <main className={`app phase-${phase.toLowerCase()}`}>
      <div className="grain" aria-hidden="true" />
      <header className="top-rail">
        <div className="brand">SNE <span>// CYBER INTELLIGENCE</span></div>
        <div className="operation-state"><i /> {phase === "IDLE" ? "SYSTEM READY" : phase === "ANALYZING" ? "DEFENSIVE OBSERVATION ACTIVE" : phase === "ERROR" ? "OBSERVATION INCOMPLETE" : "INTELLIGENCE BRIEF ACTIVE"}</div>
        <div className="protocol">CELO MAINNET <span>|</span> X402 {offer?.available ? "ONLINE" : "UNAVAILABLE"}</div>
      </header>

      <section className="workspace">
        <div className="title-block">
          <div className="eyebrow">EVIDENCE-BACKED / PASSIVE COLLECTION</div>
          <h1>Security<br />Passport</h1>
          <p>Observe the public surface.<br />Understand the posture.<br />Prove the change.</p>
        </div>

        <div className="graph-stage">
          <AmbientGraph phase={phase} origin={origin} preview={preview} />
          {(phase === "IDLE" || phase === "ERROR") && (
            <form className="origin-command" onSubmit={submit}>
              <label htmlFor="target">PUBLIC ORIGIN</label>
              <div className="command-input">
                <span>⌁</span>
                <input id="target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://yourproject.xyz" autoComplete="url" inputMode="url" />
                <button type="submit" disabled={!target.trim()} aria-label="Begin assessment">OBSERVE <b>→</b></button>
              </div>
              <small>Non-invasive public-origin assessment. No exploitation or intrusive probing.</small>
            </form>
          )}
          {phase === "ANALYZING" && (
            <div className="live-note" role="status"><i /> Assessment request remains in progress. No intermediate technical state is asserted.</div>
          )}
          {error && <div className="error-note" role="alert">{error}</div>}
        </div>

        <PublicBrief preview={preview} />
      </section>

      <IntelTimeline events={events} elapsed={phase === "ANALYZING" ? elapsed : 0} />

      <footer className="access-rail">
        <div className="classification"><span>CLASSIFICATION</span><strong>{preview ? "PUBLIC PREVIEW" : "PUBLIC"}</strong></div>
        <div className="mission">SNE LABS <span>Evidence before trust.</span></div>
        {preview && phase !== "UNLOCKED" && (
          <button className="unlock" onClick={unlock} disabled={busy || !offer?.available}>
            <span className="lock">⌾</span>
            <span><small>FULL ASSESSMENT // CONTROLLED ACCESS</small><strong>{phase === "UNLOCKING" ? "AWAITING WALLET / SETTLEMENT" : `UNLOCK · ${formatPrice(policy)} · CELO`}</strong></span>
            <b>→</b>
          </button>
        )}
        {phase === "UNLOCKED" && fullReview && (
          <div className="delivered">
            <small>FULL ASSESSMENT // DELIVERED</small>
            <strong>{fullReview.findings.length} FINDINGS · {fullReview.evidence.length} EVIDENCE RECORDS</strong>
            <span title={fullReview.result_digest}>{shortId(fullReview.result_digest)}</span>
          </div>
        )}
      </footer>
    </main>
  );
}
