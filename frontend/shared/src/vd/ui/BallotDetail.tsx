import { useTranslation } from "react-i18next";
import { Hex } from "./Hex";
import { StatusIcon } from "./StatusIcon";
import type { Ballot } from "../eth/types";

type VerifyState =
  | { status: "idle" }
  | { status: "verifying"; token: number }
  | { status: "ok"; token: number }
  | { status: "bad"; reason: string; token: number };

function hexBytesLen(hex: string): number {
  if (!hex || hex === "0x") return 0;
  if (!hex.startsWith("0x")) return 0;
  return Math.max(0, (hex.length - 2) / 2);
}

type Props = {
  ballot: Ballot;
  globalIndex: number;
  verifyState: VerifyState;
  onBack: () => void;
  onVerifyLocally: () => void;
  onToggleGuide: () => void;
  guideOpen: boolean;
  txHash?: string | null;
  explorerUrl?: string;
  /** The election's scale: the tally counts each weight divided by it, rounded half-up. */
  scale?: number;
};

/** What the tally counts for a held weight: `(w + s/2) / s`, as `scaled_weight` in Python. */
export function countedWeight(weight: bigint, scale: bigint): bigint {
  return (weight + scale / 2n) / scale;
}

export function BallotDetail({ ballot, globalIndex, verifyState, onBack, onVerifyLocally, onToggleGuide, guideOpen, txHash, explorerUrl, scale = 1 }: Props) {
  // The credential's exact weight: `ballot.weight` is a JS number, rounded above 2^53.
  const exactWeight = ballot.attestation ? BigInt(ballot.attestation.weight) : BigInt(ballot.weight);
  const scaleN = BigInt(scale);
  const counted = countedWeight(exactWeight, scaleN);
  const { t } = useTranslation();
  const vs = verifyState.status;
  const iconType = vs === "ok" ? "ok" : vs === "bad" ? "bad" : vs === "verifying" ? "checking" : "idle";
  const explorerTxUrl = explorerUrl && txHash ? `${explorerUrl}/tx/${txHash}` : null;

  return (
    <div className="bdContainer">
      <button type="button" className="bdBack" onClick={onBack}>
        {t("← Back to ballots")}
      </button>

      <div className="bdBallotLabel">{t("BALLOT")}</div>
      <h2 className="bdBallotIndex">{t("Index {{n}}", { n: globalIndex })}</h2>

      <div className="bdPseudonymRow">
        <span className="dim">pseudonym</span>
        <Hex value={ballot.pseudonym} trim={20} />
      </div>

      <div className="bdPseudonymRow">
        <span className="dim">counted at weight</span>
        <span className="mono">
          {counted.toLocaleString()}
          {counted === 1n ? "" : t(" (each point counts {{n}}x)", { n: counted.toLocaleString() })}
          {scaleN === 1n ? "" : t(" · held {{w}} ÷ scale {{s}}", { w: exactWeight.toLocaleString(), s: scaleN.toLocaleString() })}
        </span>
      </div>

      <div className="bdTxRow">
        <span className="dim">transaction</span>
        {explorerTxUrl ? (
          <a
            href={explorerTxUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="bdTxLink mono"
          >
            <Hex value={txHash!} trim={20} />
          </a>
        ) : txHash === undefined ? (
          <span className="dim">{t("Loading…")}</span>
        ) : (
          <span className="dim">—</span>
        )}
      </div>

      {/* Status card */}
      <div className={`bdStatusCard bdStatusCard--${iconType}`}>
        <div className="bdStatusIcon">
          <StatusIcon type={iconType} />
        </div>
        <div className="bdStatusBody">
          {vs === "ok" && (
            <>
              <div className="bdStatusTitle">{t("VALID")}</div>
              <div className="bdStatusDesc">
                {t("All cryptographic checks passed · WR attestation, ZK proofs, voter signature, field decoding.")}
              </div>
            </>
          )}
          {vs === "bad" && (
            <>
              <div className="bdStatusTitle">{t("INVALID")}</div>
              <div className="bdStatusDesc">
                {(verifyState as Extract<VerifyState, { status: "bad" }>).reason}
              </div>
            </>
          )}
          {vs === "verifying" && (
            <>
              <div className="bdStatusTitle">{t("Verifying…")}</div>
              <div className="bdStatusDesc">{t("Running cryptographic checks in the background.")}</div>
            </>
          )}
          {vs === "idle" && (
            <>
              <div className="bdStatusTitle">{t("Not verified yet")}</div>
              <div className="bdStatusDesc">{t("Run the cryptographic checks for this ballot in your browser.")}</div>
              <button type="button" className="verifyYourselfBtn" style={{ marginTop: 10 }} onClick={onVerifyLocally}>
                {t("Verify ballot")}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Details section */}
      <div className="bdSection">
        <div className="bdSectionLabel">{t("DETAILS")}</div>
        <div className="bdGrid mono">
          <div className="dim">vk</div>
          <div>
            <Hex value={ballot.vk} trim={26} />{" "}
            <span className="dim">{t("({{n}} bytes)", { n: hexBytesLen(ballot.vk) })}</span>
          </div>

          <div className="dim">ciphertexts</div>
          <div>
            {ballot.ciphertexts.map((ct, j) => (
              <div key={j} className="bdCiphertext">
                <div className="dim bdCandidateLabel">{t("candidate {{n}}", { n: j })}</div>
                <div className="bdCipherRow">
                  <span className="dim">c1</span>
                  <Hex value={ct.c1} trim={20} />
                </div>
                <div className="bdCipherRow">
                  <span className="dim">c2</span>
                  <Hex value={ct.c2} trim={20} />
                </div>
              </div>
            ))}
          </div>

          <div className="dim">zkProof</div>
          <div>
            <Hex value={ballot.zkProof} trim={26} />
          </div>

          <div className="dim">voterSignature</div>
          <div>
            <Hex value={ballot.voterSignature} trim={26} />
          </div>

          <div className="dim">credential signature</div>
          <div>
            {ballot.attestation ? <Hex value={ballot.attestation.signature} trim={26} /> : <span className="dim">—</span>}
          </div>

          <div className="dim">credential weight · nonce</div>
          <div className="mono">
            {ballot.attestation ? `${ballot.attestation.weight} · ${ballot.attestation.nonce}` : "—"}
          </div>
        </div>
      </div>

      {/* Verify yourself section */}
      <div className="verifyYourselfSection">
        <div className="verifyYourselfLabel">{t("VERIFY YOURSELF")}</div>
          <p className="verifyYourselfDesc">
            {t("Don't trust this panel · re-run the same cryptographic check yourself, against this stage's on-chain data, on your own machine.")}
          </p>
          <button type="button" className="verifyYourselfBtn" onClick={onToggleGuide}>
            {guideOpen ? t("Hide manual guide ↑") : t("Open manual verification guide →")}
          </button>
      </div>
    </div>
  );
}
