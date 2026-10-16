// Run the SDK's own verifyBallot over a ballot vector (the tests/vectors/ballot schema).
// Exits 0 when the verdict matches `expected.verify`. Uses the SDK the frontend installs.
//
//   node tests/sdk/verify_ballot.mjs <vector.json>
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const require = createRequire(join(root, 'frontend', 'package.json'));
const { initCurves, G2Point, verifyBallot } = require('@shutter-network/urban-verified-crypto');

const unhex = (h) => new Uint8Array(Buffer.from(String(h).replace(/^0x/, ''), 'hex'));

await initCurves();
const v = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const i = v.inputs;
const a = i.attestation;
const inputs = {
  electionId: unhex(i.election_id),
  pseudonym: unhex(i.pseudonym),
  vk: unhex(i.vk),
  ciphertexts: i.ciphertexts.map((c) => [unhex(c.c1), unhex(c.c2)]),
  zkProof: unhex(i.zkProof),
  voterSignature: unhex(i.signature),
  attestation: {
    electionId: unhex(a.electionId), pseudonym: unhex(a.pseudonym), vk: unhex(a.vk),
    weight: BigInt(a.weight), nonce: BigInt(a.nonce), signature: unhex(a.signature),
  },
};
const r = verifyBallot(inputs, i.params, G2Point.fromBytes(unhex(i.mpk)), unhex(i.eligibility_key));
console.log(JSON.stringify(r));
process.exit(r.ok === v.expected.verify ? 0 : 1);
