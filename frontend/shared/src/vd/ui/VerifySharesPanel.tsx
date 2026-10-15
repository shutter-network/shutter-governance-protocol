import { useTranslation } from "react-i18next";
import type { DecryptionShare, EncryptedTally, ElectionConfigView, DkgResultView } from "../eth/types";
import { CodeBlock } from "./CodeBlock";

import { SDK_PACKAGE, SDK_VERSION } from "./sdk";

type Props = {
  overview: { config: ElectionConfigView; dkg: DkgResultView };
  aggregate: EncryptedTally;
  shares: DecryptionShare[];
  selectedElection: string;
};

export function VerifySharesPanel({ overview, aggregate, shares, selectedElection }: Props) {
  const { t } = useTranslation();
  const fixtureFilename = "shares-fixture.json";
  const scriptName = "verify-shares.js";

  function downloadFixture() {
    const fixture = {
      electionId: overview.config.electionId.toString(),
      numCandidates: overview.config.numCandidates,
      threshold: overview.config.thresholdT.toString(),
      aggregate: aggregate.aggregates.map((ct) => ({ c1: ct.c1, c2: ct.c2 })),
      committeePks: overview.dkg.committeePKs,
      shares: shares.map((s) => ({
        keyperIndex: s.keyperIndex,
        shares: s.shares,
        proofs: s.proofs.map((p) => p ? { e: p.e.toString(), z: p.z.toString() } : null),
      })),
      electionAddress: selectedElection,
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(fixture, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fixtureFilename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const installCmd = `npm install ${SDK_PACKAGE}@${SDK_VERSION}`;

  const scriptCode = [
    `const { initCurves, G2Point, Transcript, verifyDecryptionShare } = require("${SDK_PACKAGE}");`,
    `const { readFileSync } = require("node:fs");`,
    `const fromHex = (h) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));`,
    `const g2FromHex = (h) => G2Point.fromBytes(fromHex(h));`,
    `const electionId32 = (id) => fromHex(BigInt(id).toString(16).padStart(64, "0"));`,
    `const decryptTranscript = (electionIdBytes, j) => { const t = new Transcript("SHUTTER-VOTE-DECRYPT-v1"); t.append("electionId", electionIdBytes); t.append("candidate", new Uint8Array([(j >> 8) & 255, j & 255])); return t; };`,
    `async function main() {`,
    `  const f = JSON.parse(readFileSync("${fixtureFilename}", "utf8"));`,
    `  await initCurves();`,
    `  const electionIdBytes = electionId32(f.electionId);`,
    `  let ok = true;`,
    `  for (const s of f.shares) {`,
    `    // keyperIndex is 1-based; committeePks is indexed from 0.`,
    `    const pk = g2FromHex(f.committeePks[s.keyperIndex - 1]);`,
    `    for (let j = 0; j < f.numCandidates; j++) {`,
    `      const ct = { c1: g2FromHex(f.aggregate[j].c1), c2: g2FromHex(f.aggregate[j].c2) };`,
    `      const share = { keyperIndex: s.keyperIndex, sigma: g2FromHex(s.shares[j]), proof: { e: BigInt(s.proofs[j].e), z: BigInt(s.proofs[j].z) } };`,
    `      const valid = verifyDecryptionShare(ct, share, pk, decryptTranscript(electionIdBytes, j));`,
    `      if (!valid) ok = false;`,
    `      console.log(\`Keyper \${s.keyperIndex}, candidate \${j}: \${valid ? "✓ valid" : "✗ invalid"}\`);`,
    `    }`,
    `  }`,
    `  console.log(ok ? "\\n✓ All shares verified" : "\\n✗ Invalid shares detected");`,
    `  process.exit(ok ? 0 : 1);`,
    `}`,
    `main().catch((e) => { console.error(e); process.exit(2); });`,
  ].join("\n");

  const exampleLines = shares.flatMap((s) =>
    Array.from({ length: overview.config.numCandidates }, (_, j) =>
      `Keyper ${s.keyperIndex}, candidate ${j}: ✓ valid`
    )
  ).slice(0, 6);
  const expectedOutput = [...exampleLines, "...", "", "✓ All shares verified"].join("\n");

  return (
    <div className="vpInline" role="region" aria-label={t("Decryption shares verification guide")}>
      <div className="vpInlineHdr">
        <div>
          <div className="vpHeaderLabel">{t("RE-VERIFY DECRYPTION SHARES LOCALLY")}</div>
          <div className="vpHeaderSub">
            {shares.length === 1
              ? t("1 keyper · {{n}} candidates each", { n: overview.config.numCandidates })
              : t("{{count}} keypers · {{n}} candidates each", { count: shares.length, n: overview.config.numCandidates })}
          </div>
        </div>
      </div>

      <div className="vpBody">
        <p className="vpIntro">
          {t("Confirm that each keyper's decryption share is cryptographically bound to their committee public key. A DLEQ proof is published alongside every share · verify it yourself to rule out fabricated or corrupted shares.")}
        </p>

        <div className="vpStep">
          <div className="vpStepNum">1</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Download the shares fixture")}</div>
            <p className="vpStepDesc">
              {t("Contains the on-chain aggregate, all keyper decryption shares with their DLEQ proofs, and the committee public keys.")}
            </p>
            <button type="button" className="vpDownloadBtn" onClick={downloadFixture}>
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M6.5 1v8M3 6l3.5 3.5L10 6" />
                <path d="M1 11h11" />
              </svg>
              {fixtureFilename}
            </button>
          </div>
        </div>

        <div className="vpStep">
          <div className="vpStepNum">2</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Install the Shutter crypto SDK")}</div>
            <CodeBlock>{installCmd}</CodeBlock>
          </div>
        </div>

        <div className="vpStep">
          <div className="vpStepNum">3</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Write and run the verification script")}</div>
            <p className="vpStepDesc">
              {t("Save as")} <span className="mono">{scriptName}</span> {t("next to the fixture, then run:")}
            </p>
            <CodeBlock>{scriptCode}</CodeBlock>
            <CodeBlock>{`node ${scriptName}`}</CodeBlock>
            <div className="vpExpectedLabel">{t("Expected output")}</div>
            <pre className="vpExpectedOutput">{expectedOutput}</pre>
            <p className="vpStepDesc" style={{ marginTop: 8 }}>
              {t("Exit code 0 = all shares valid. Exit code 1 = at least one share failed.")}
            </p>
          </div>
        </div>

        <div className="vpSection">
          <div className="vpSectionLabel">{t("WHAT'S BEING CHECKED")}</div>
          <div className="vpCheckList">
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("DLEQ proof per share")}</div>
              <div className="vpCheckDesc">
                {t("Each share σ_i = s_i · C₁ (on the aggregate ciphertext) is accompanied by a discrete-log equality proof showing the same secret s_i produced σ_i and the keyper's committee public key (G₂). This prevents a corrupted or fabricated share from passing undetected.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Per-keyper, per-candidate")}</div>
              <div className="vpCheckDesc">
                {t("Every keyper must submit one valid share per candidate ciphertext. All shares are checked independently · a single bad share is flagged.")}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
