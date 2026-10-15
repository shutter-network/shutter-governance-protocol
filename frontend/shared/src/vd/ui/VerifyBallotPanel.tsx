import { useTranslation } from "react-i18next";
import type { Ballot, ElectionConfigView, DkgResultView } from "../eth/types";
import { CodeBlock } from "./CodeBlock";

import { SDK_PACKAGE, SDK_VERSION } from "./sdk";

type Props = {
  ballot: Ballot;
  globalIndex: number;
  overview: { config: ElectionConfigView; dkg: DkgResultView };
  selectedElection: string;
};

export function VerifyBallotPanel({ ballot, globalIndex, overview, selectedElection }: Props) {
  const { t } = useTranslation();
  const fixtureFilename = `ballot-${globalIndex}-fixture.json`;
  const scriptName = `verify-ballot-${globalIndex}.js`;

  function downloadFixture() {
    const fixture = {
      mpkElectionG2: overview.dkg.pkElection,
      pkWrG1: overview.config.pkWR,
      electionId: overview.config.electionId.toString(),
      numCandidates: overview.config.numCandidates,
      budget: overview.config.budget,
      // Munich defaults · adjust if election uses atMost mode or Variant B
      mode: "exact",
      variant: "A",
      ballots: [ballot],
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
    `const { initCurves, G2Point, verifyBallot } = require("${SDK_PACKAGE}");`,
    `const { readFileSync } = require("node:fs");`,
    `const fromHex = (h) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));`,
    `const electionId32 = (id) => fromHex(BigInt(id).toString(16).padStart(64, "0"));`,
    `async function main() {`,
    `  const f = JSON.parse(readFileSync("${fixtureFilename}", "utf8"));`,
    `  const b = f.ballots?.[0];`,
    `  if (!b) throw new Error("Fixture missing ballots[0]");`,
    `  if (!b.attestation) { console.log(\`✗ INVALID: malformed record (\${b.malformed})\`); process.exit(1); }`,
    `  await initCurves();`,
    `  // The eligibility credential is checked against the issuer's key (pkWrG1) and must`,
    `  // belong to this ballot; the voter's signature covers it.`,
    `  const a = b.attestation;`,
    `  const res = verifyBallot(`,
    `    { electionId: electionId32(f.electionId), pseudonym: fromHex(b.pseudonym), vk: fromHex(b.vk),`,
    `      ciphertexts: b.ciphertexts.map(({ c1, c2 }) => [fromHex(c1), fromHex(c2)]),`,
    `      zkProof: fromHex(b.zkProof), voterSignature: fromHex(b.voterSignature),`,
    `      attestation: { electionId: electionId32(a.electionId), pseudonym: fromHex(a.pseudonym), vk: fromHex(a.vk),`,
    `                     weight: BigInt(a.weight), nonce: BigInt(a.nonce), signature: fromHex(a.signature) } },`,
    `    { numCandidates: f.numCandidates, budget: f.budget, mode: f.mode ?? "exact", variant: f.variant ?? "A" },`,
    `    G2Point.fromBytes(fromHex(f.mpkElectionG2)),`,
    `    fromHex(f.pkWrG1),`,
    `  );`,
    `  console.log(res.ok ? "✓ VALID" : \`✗ INVALID: \${res.reason}\`);`,
    `  process.exit(res.ok ? 0 : 1);`,
    `}`,
    `main().catch((e) => { console.error(e); process.exit(2); });`,
  ].join("\n");

  const runCmd = `node ${scriptName}`;

  return (
    <div className="vpInline" role="region" aria-label={t("Local verification guide")}>
      <div className="vpInlineHdr">
        <div>
          <div className="vpHeaderLabel">{t("RE-VERIFY THIS BALLOT LOCALLY")}</div>
          <div className="vpHeaderSub">{t("Ballot Index {{n}}", { n: globalIndex })}</div>
        </div>
      </div>

      <div className="vpBody">
        <p className="vpIntro">
          {t("Run the same cryptographic checks the dashboard performs, on your own machine, against this specific ballot. A clean local check means you don't need to trust the dashboard.")}
        </p>

        <div className="vpStep">
          <div className="vpStepNum">1</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Download this ballot's fixture")}</div>
            <p className="vpStepDesc">
              {t("A self-contained JSON file with all election parameters and this ballot only.")}
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
            <div className="vpStepTitle">{t("Write and run a verification script")}</div>
            <p className="vpStepDesc">
              {t("Save as")} <span className="mono">{scriptName}</span> {t("in the same directory as the fixture, then run:")}
            </p>
            <CodeBlock>{scriptCode}</CodeBlock>
            <CodeBlock>{runCmd}</CodeBlock>
            <div className="vpExpectedLabel">{t("Expected output")}</div>
            <pre className="vpExpectedOutput">✓ VALID</pre>
            <p className="vpStepDesc" style={{ marginTop: 8 }}>
              {t("Exit code 0 = all checks passed. Exit code 1 = ballot is invalid.")}
            </p>
          </div>
        </div>

        <div className="vpSection">
          <div className="vpSectionLabel">{t("WHAT'S BEING CHECKED")}</div>
          <div className="vpCheckList">
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("WR attestation")}</div>
              <div className="vpCheckDesc">
                {t("The voter's pseudonym is registered for this election, with an authorized weight.")}{" "}
                {t("The eligibility authority's Schnorr key (pkWR) signs a domain-separated transcript")}{" "}
                <span className="mono" style={{ fontSize: 11 }}>SHUTTER-VOTE-ATTEST-v1(electionId, pseudonym, vk, weight)</span>{" "}
                {t("(ATTESTATION_V1); a legacy weightless credential over")}{" "}
                <span className="mono" style={{ fontSize: 11 }}>keccak256(electionId ‖ pseudonym ‖ vk)</span>{" "}
                {t("is also accepted at weight 1. Verified via")}{" "}
                <span className="mono" style={{ fontSize: 11 }}>schnorrVerify</span>.
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("ZK range proofs")}</div>
              <div className="vpCheckDesc">
                {t("For each candidate, a zero-knowledge proof shows the encrypted vote is within the allowed budget · no over-voting, without revealing the actual choice.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Voter Schnorr signature")}</div>
              <div className="vpCheckDesc">
                {t("The ballot bytes are bound to the voter's ephemeral public key (vk), preventing replay or modification after submission.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Field decoding")}</div>
              <div className="vpCheckDesc">
                {t("vk and Schnorr components are decoded as compressed G₁ points (48 bytes); ciphertexts (c1, c2) and the election public key as G₂ (96 bytes) · all subgroup-checked before verification runs.")}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
