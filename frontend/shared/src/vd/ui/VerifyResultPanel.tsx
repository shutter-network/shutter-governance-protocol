import { useTranslation } from "react-i18next";
import type { DecryptionShare, EncryptedTally, ElectionConfigView, DkgResultView, ElectionResult } from "../eth/types";
import { CodeBlock } from "./CodeBlock";

import { SDK_PACKAGE, SDK_VERSION } from "./sdk";

type Props = {
  overview: { config: ElectionConfigView; dkg: DkgResultView };
  aggregate: EncryptedTally;
  shares: DecryptionShare[];
  result: ElectionResult;
  totalBallots: bigint;
  selectedElection: string;
};

export function VerifyResultPanel({ overview, aggregate, shares, result, totalBallots, selectedElection }: Props) {
  const { t } = useTranslation();
  const fixtureFilename = "result-fixture.json";
  const scriptName = "verify-result.js";

  function downloadFixture() {
    const fixture = {
      electionId: overview.config.electionId.toString(),
      numCandidates: overview.config.numCandidates,
      threshold: overview.config.thresholdT.toString(),
      totalBallots: totalBallots.toString(),
      budget: overview.config.budget,
      bsgsBound: result.bsgsBound.toString(),
      aggregate: aggregate.aggregates.map((ct) => ({ c1: ct.c1, c2: ct.c2 })),
      committeePks: overview.dkg.committeePKs,
      shares: shares.map((s) => ({
        keyperIndex: s.keyperIndex,
        shares: s.shares,
        proofs: s.proofs.map((p) => p ? { e: p.e.toString(), z: p.z.toString() } : null),
      })),
      tally: result.tally.map((v) => v.toString()),
      keyperIndices: result.keyperIndices,
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
    `const { initCurves, G2Point, Transcript, verifyDecryptionShare, combineShares, buildBabyStepTable, recoverDiscreteLogWithTable } = require("${SDK_PACKAGE}");`,
    `const { readFileSync } = require("node:fs");`,
    `const fromHex = (h) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));`,
    `const g2FromHex = (h) => G2Point.fromBytes(fromHex(h));`,
    `const electionId32 = (id) => fromHex(BigInt(id).toString(16).padStart(64, "0"));`,
    `const decryptTranscript = (electionIdBytes, j) => { const t = new Transcript("SHUTTER-VOTE-DECRYPT-v1"); t.append("electionId", electionIdBytes); t.append("candidate", new Uint8Array([(j >> 8) & 255, j & 255])); return t; };`,
    `async function main() {`,
    `  const f = JSON.parse(readFileSync("${fixtureFilename}", "utf8"));`,
    `  const threshold = Number(f.threshold);`,
    `  await initCurves();`,
    `  // BSGS bound = budget · Σ(admitted weights), published as bsgsBound (plain`,
    `  // totalBallots·budget underflows a weighted tally where weights exceed 1).`,
    `  const electionIdBytes = electionId32(f.electionId), babyStepTable = buildBabyStepTable(BigInt(f.bsgsBound));`,
    `  const totals = [];`,
    `  for (let j = 0; j < f.numCandidates; j++) {`,
    `    const ct = { c1: g2FromHex(f.aggregate[j].c1), c2: g2FromHex(f.aggregate[j].c2) };`,
    `    const valid = [];`,
    `    for (const s of f.shares) {`,
    `      // keyperIndex is 1-based; committeePks is indexed from 0.`,
    `      const share = { keyperIndex: s.keyperIndex, sigma: g2FromHex(s.shares[j]), proof: { e: BigInt(s.proofs[j].e), z: BigInt(s.proofs[j].z) } };`,
    `      if (verifyDecryptionShare(ct, share, g2FromHex(f.committeePks[s.keyperIndex - 1]), decryptTranscript(electionIdBytes, j))) valid.push(share);`,
    `      if (valid.length >= threshold) break;`,
    `    }`,
    `    if (valid.length < threshold) throw new Error(\`Candidate \${j}: only \${valid.length} valid shares (need \${threshold})\`);`,
    `    totals.push(recoverDiscreteLogWithTable(combineShares(valid, valid.map((sh) => BigInt(sh.keyperIndex)), ct), babyStepTable));`,
    `  }`,
    `  let ok = true;`,
    `  for (let j = 0; j < f.numCandidates; j++) {`,
    `    const pub = BigInt(f.tally[j]), match = totals[j] === pub;`,
    `    if (!match) ok = false;`,
    `    console.log(\`Candidate \${j}: \${totals[j]} votes \${match ? "✓" : \`✗ published=\${pub}\`}\`);`,
    `  }`,
    `  console.log(ok ? "\\n✓ Tally verified" : "\\n✗ Tally mismatch");`,
    `  process.exit(ok ? 0 : 1);`,
    `}`,
    `main().catch((e) => { console.error(e); process.exit(2); });`,
  ].join("\n");

  const tallyLines = result.tally.map((v, j) => `Candidate ${j}: ${v} votes ✓`).join("\n");
  const expectedOutput = `${tallyLines}\n\n✓ Tally verified`;

  return (
    <div className="vpInline" role="region" aria-label={t("Final tally verification guide")}>
      <div className="vpInlineHdr">
        <div>
          <div className="vpHeaderLabel">{t("RE-VERIFY THE FINAL TALLY LOCALLY")}</div>
          <div className="vpHeaderSub">
            {t("{{n}} candidates · {{votes}} total votes", {
              n: result.tally.length,
              votes: result.tally.reduce((s, c) => s + c, 0n).toString(),
            })}
          </div>
        </div>
      </div>

      <div className="vpBody">
        <p className="vpIntro">
          {t("Independently decrypt the aggregate using the keyper shares and reproduce the published vote counts yourself. If your numbers match, the tally is genuine · no trust in the dashboard required.")}
        </p>

        <div className="vpStep">
          <div className="vpStepNum">1</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Download the result fixture")}</div>
            <p className="vpStepDesc">
              {t("Contains the aggregate ciphertexts, all keyper decryption shares, committee public keys, election parameters, and the published tally to compare against.")}
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
              {t("Exit code 0 = tally reproduced and matches. Exit code 1 = mismatch or insufficient shares.")}
            </p>
          </div>
        </div>

        <div className="vpSection">
          <div className="vpSectionLabel">{t("WHAT'S BEING CHECKED")}</div>
          <div className="vpCheckList">
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Share validity (DLEQ)")}</div>
              <div className="vpCheckDesc">
                {t("Each share is verified against its keyper's committee public key before use. Only shares passing the DLEQ proof are Lagrange-combined.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Threshold decryption")}</div>
              <div className="vpCheckDesc">
                {t("The first t verified shares are Lagrange-combined to remove the encryption mask from each candidate's aggregate ciphertext, without ever assembling the full private key.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Baby-step / giant-step")}</div>
              <div className="vpCheckDesc">
                {t("After decryption, a discrete-log solver recovers the integer vote count from a G₂ point. The search space is bounded by budget × Σ(admitted weights) — the published bsgsBound.")}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
