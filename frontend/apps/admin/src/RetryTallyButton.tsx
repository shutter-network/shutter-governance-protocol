import { useCallback, useEffect, useState } from "react";
import { api, deriveState, eidToBareHex, eidToHex, formatApiError, retryTally, type ElectionRecord } from "@shutter-governance-protocol/shared";
import { type WalletSigner } from "@shutter-governance-protocol/shared/wallet";
import { retryTallyDigest } from "./adminSign";

type Status = { kind: "ok" | "err" | "info"; msg: string } | null;

/** "Retry tally" — surfaces only when the tally is **stalled** (the coordinator abandoned it
 * after exhausting its attempts). The admin wallet signs a clear (`tally_resume`), which the
 * admin service relays; the coordinator then resumes with a fresh budget. A restart alone
 * will not resume a stall — this button is the way out. Bring the keypers back online first;
 * retrying while they are still down just re-stalls. */
export function RetryTallyButton({ electionId, wallet }: { electionId: number; wallet: WalletSigner | null }) {
  const [stalled, setStalled] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const rec: ElectionRecord = await api.getElection(electionId);
      const res = await api.getResult(electionId);
      const now = Math.floor(Date.now() / 1000);
      const state = deriveState(rec.config, {
        cancelled: rec.cancelled,
        keyFinalized: rec.finalizedKey != null,
        resultPublished: res.result != null,
        tallyStalled: rec.tallyStalled,
      }, now);
      setStalled(state === "TallyStalled");
    } catch { /* transient */ }
  }, [electionId]);

  useEffect(() => {
    load();
    const h = setInterval(load, 5000); // refresh so it appears/disappears as the stall toggles
    return () => clearInterval(h);
  }, [load]);

  if (!stalled) return null; // only shown while the tally is stalled
  const connected = !!wallet?.account;

  const retry = async () => {
    if (!wallet) return;
    setBusy(true);
    setStatus({ kind: "info", msg: "Awaiting wallet signature…" });
    try {
      // One timestamp for both: the signature covers it and the service checks it.
      const issuedAt = Math.floor(Date.now() / 1000);
      const signature = await wallet.signDigest(retryTallyDigest(eidToHex(electionId), issuedAt));
      await retryTally(eidToBareHex(electionId), signature, issuedAt);
      setStatus({ kind: "ok", msg: `Retry requested for election #${electionId}` });
      load();
    } catch (e: unknown) {
      setStatus({ kind: "err", msg: formatApiError(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: "inline-flex", flexDirection: "column", alignItems: "flex-end" }}>
      <button className="btn btn--primary btn--sm" disabled={!connected || busy} onClick={retry}>
        {busy ? "Retrying…" : "Retry tally"}
      </button>
      <div className="dim" style={{ fontSize: 11, marginTop: 5, textAlign: "right", whiteSpace: "nowrap" }}>
        {connected ? "Tally stalled, make sure keypers are online, then retry." : "Connect the admin wallet to retry."}
      </div>
      {status && (
        <div className={`notice notice--${status.kind === "ok" ? "ok" : status.kind === "err" ? "err" : "info"}`} style={{ marginTop: 6, textAlign: "right" }}>
          {status.msg}
        </div>
      )}
    </div>
  );
}
