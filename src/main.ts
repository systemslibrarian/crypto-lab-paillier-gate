import {
  addCiphertexts,
  decrypt,
  encrypt,
  multiplyByScalar,
  rerandomize,
  traceDecryption,
  type DecryptionStep,
  type PaillierKeyPair,
} from './paillier';
import { simulatePrivateAggregation, weightedSum } from './aggregation';
import {
  forgeBallot,
  generateBallotKey,
  runBallotBox,
  sealBallots,
  tagCiphertext,
  type SealedBallot,
} from './ballots';
import {
  DEFAULT_BUDGET,
  expectedIterations,
  keyPairFromRecovered,
  recoverPrivateKey,
  type FactorResult,
} from './factor';
import './style.css';

type GenerateRequest = {
  type: 'generate';
  bitLength: number;
};

type ProgressMessage = {
  type: 'progress';
  stage: string;
  percent: number;
};

type SuccessMessage = {
  type: 'success';
  keyPair: PaillierKeyPair;
};

type ErrorMessage = {
  type: 'error';
  message: string;
};

type WorkerMessage = ProgressMessage | SuccessMessage | ErrorMessage;

type FactorWorkerMessage =
  | { type: 'progress'; iterations: number }
  | { type: 'done'; result: FactorResult }
  | { type: 'error'; message: string };

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found.');
}

app.innerHTML = `
  <main class="shell" id="main" tabindex="-1">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Paillier</h1>
        <p class="cl-hero-sub">Additively Homomorphic · Public-Key Encryption</p>
        <p class="cl-hero-desc">Generate a keypair, encrypt separate numbers, then add and scale those ciphertexts so decrypting only the combined result reveals the final sum.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">
          It lets an aggregator tally private inputs it can never read: the raw values stay sealed and only the total comes out. That powers privacy-preserving voting, analytics, and billing where individual numbers must stay secret.
        </p>
      </aside>
    </header>

    <section class="panel panel-wide">
      <div class="section-heading">
        <div>
          <p class="section-kicker">Step 1</p>
          <h2>Generate a keypair</h2>
        </div>
        <p class="section-copy">Use small educational key sizes here. Real deployments use much larger keys and audited libraries.</p>
      </div>

      <form id="key-form" class="control-row">
        <label class="field compact-field">
          <span>Bit length</span>
          <select id="bit-length">
            <option value="64">64-bit</option>
            <option value="96" selected>96-bit</option>
            <option value="128">128-bit</option>
            <option value="160">160-bit</option>
            <option value="192">192-bit</option>
          </select>
        </label>
        <button id="generate-key" class="button button-primary" type="submit">Generate keypair</button>
      </form>

      <div class="progress-block">
        <div class="progress-meta">
          <span id="key-status" role="status" aria-live="polite">No keypair loaded.</span>
          <span id="key-percent">0%</span>
        </div>
        <div
          class="progress-track"
          role="progressbar"
          aria-labelledby="key-status"
          aria-valuemin="0"
          aria-valuemax="100"
          aria-valuenow="0"
          id="progress-track"
        ><div id="progress-fill" class="progress-fill"></div></div>
      </div>

      <div class="key-grid">
        <article class="metric-card">
          <span class="metric-label">Modulus bits</span>
          <strong id="metric-bits">-</strong>
          <span class="metric-gloss">size of N in bits — bigger is harder to factor</span>
        </article>
        <article class="metric-card">
          <span class="metric-label">Public modulus N</span>
          <code id="metric-n">Generate a keypair to populate this field.</code>
          <span class="metric-gloss">public modulus N = p·q — shared freely, hides the two secret primes</span>
        </article>
        <article class="metric-card">
          <span class="metric-label">Generator g</span>
          <code id="metric-g">-</code>
          <span class="metric-gloss">generator, fixed to N+1 — makes gᵐ = 1 + mN mod N², so the exponent m is recoverable</span>
        </article>
        <article class="metric-card">
          <span class="metric-label">Private λ</span>
          <code id="metric-lambda">-</code>
          <span class="metric-gloss">private trapdoor λ = lcm(p−1, q−1) — the secret that unlocks decryption</span>
        </article>
      </div>

      <div class="attack-block" id="factor-block">
        <h3 class="attack-title">Attack the key: factor N</h3>
        <p class="section-copy">
          The private key <em>is</em> the factorisation. Run a real Pollard rho (Brent's variant) against the
          modulus above: if it splits <code>N</code> into <code>p·q</code>, this page rebuilds
          <code>λ = lcm(p−1, q−1)</code> from those primes and decrypts your ciphertext with the key it just derived.
          At larger sizes the same routine runs out of budget — that is the wall the bit-length selector is really about,
          measured rather than captioned.
        </p>
        <div class="button-row">
          <button id="factor-key" class="button" type="button" disabled>Factor N (budget: <span id="factor-budget"></span> steps)</button>
        </div>
        <div id="factor-result" class="result-box" role="status" aria-live="polite">Generate a keypair, then try to break it.</div>
      </div>

      <details class="explainer">
        <summary>What's happening under the hood</summary>
        <div class="explainer-body">
          <p>
            Paillier rests on the <em>decisional composite residuosity</em> assumption. Key generation picks two primes
            <code>p</code> and <code>q</code>, forms the modulus <code>N = p·q</code>, and fixes the generator
            <code>g = N + 1</code>.
          </p>
          <p>
            A plaintext <code>m</code> is encrypted as <code>c = gᵐ · rᴺ mod N²</code> using fresh randomness
            <code>r</code>, so the same message yields a different ciphertext every time (that is the
            <strong>semantic security</strong> you will see in Step 2). Decryption recovers <code>m</code> with the
            private values <code>λ = lcm(p−1, q−1)</code> and <code>μ = λ⁻¹ mod N</code> via
            <code>m = L(c^λ mod N²) · μ mod N</code>, where <code>L(x) = (x − 1) / N</code>.
          </p>
          <p>
            The scheme is <strong>additively homomorphic</strong>: multiplying two ciphertexts modulo <code>N²</code>
            decrypts to the <em>sum</em> of their plaintexts, and raising a ciphertext to a scalar power decrypts to the
            scaled plaintext. Those two facts power Step 3 and both scenarios below. The catch: the plaintext sum must
            stay below <code>N</code>, or it wraps (Step 3 lets you trigger that on purpose).
          </p>
        </div>
      </details>
    </section>

    <section class="workspace-grid">
      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Step 2</p>
            <h2>Encrypt and decrypt</h2>
          </div>
          <p class="section-copy">Every encryption uses fresh randomness, so the same message should produce different ciphertexts.</p>
        </div>

        <form id="encrypt-form" class="stack-form">
          <label class="field">
            <span>Plaintext message</span>
            <input id="plaintext-input" inputmode="numeric" value="42" />
          </label>
          <div class="button-row">
            <button class="button" type="submit">Encrypt message</button>
            <button id="encrypt-again" class="button button-ghost" type="button" disabled>Encrypt again (same m)</button>
            <button id="rerandomize" class="button button-ghost" type="button" disabled>Re-randomize this ciphertext</button>
          </div>
        </form>

        <div class="output-stack">
          <label class="field">
            <span>Ciphertext c = gᵐ · rᴺ mod N²</span>
            <textarea id="ciphertext-output" readonly rows="4"></textarea>
          </label>
          <label class="field">
            <span>Randomizer r <span class="field-note">— the fresh random value that makes this ciphertext unique; raised to the Nth power inside c</span></span>
            <textarea id="randomizer-output" readonly rows="2"></textarea>
          </label>
        </div>

        <div class="semantic-demo" id="semantic-demo" hidden>
          <p class="semantic-demo-title">Same message, different ciphertexts</p>
          <p class="semantic-demo-copy">
            Press <em>Encrypt again</em> to stack more encryptions of the identical plaintext, or
            <em>Re-randomize this ciphertext</em> to refresh an existing ciphertext with a new <code>rᴺ</code> factor
            without knowing <code>m</code>. The ciphertexts differ completely, yet every one decrypts back to the same
            <code id="semantic-plaintext">m</code>. Each row below is decrypted with the private key as it is added, and
            the value shown is that decryption — not a repeat of what you typed. That visible gap between identical
            input and different output <em>is</em> semantic security.
          </p>
          <ol id="semantic-list" class="semantic-list" aria-label="Ciphertexts of the same plaintext"></ol>
        </div>

        <div class="handoff" id="encrypt-handoff" hidden>
          <button id="add-to-ledger" class="button button-ghost" type="button">Send this ciphertext to Step 3 →</button>
          <span class="handoff-note" id="handoff-note"></span>
        </div>

        <form id="decrypt-form" class="stack-form">
          <label class="field">
            <span>Ciphertext to decrypt</span>
            <textarea id="decrypt-input" rows="4"></textarea>
          </label>
          <button class="button" type="submit">Decrypt ciphertext</button>
        </form>

        <div id="decrypt-result" class="result-box" role="status" aria-live="polite">Generate a keypair first.</div>

        <div class="stepper" id="decrypt-stepper">
          <p class="stepper-title">Run <code>m = L(c^λ mod N²) · μ mod N</code> one step at a time</p>
          <p class="section-copy">
            Same ciphertext that is in the box above, same private key. Each press performs the next operation and
            prints the number it produced; the last one is the plaintext.
          </p>
          <div class="button-row">
            <button id="step-decrypt" class="button button-ghost" type="button" disabled>Step the decryption</button>
            <button id="reset-stepper" class="button button-ghost" type="button" disabled>Reset steps</button>
          </div>
          <ol id="stepper-list" class="stepper-list" aria-label="Decryption steps"></ol>
        </div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Step 3</p>
            <h2>Homomorphic addition</h2>
          </div>
          <p class="section-copy">Multiply two ciphertexts modulo N². The product is a brand-new ciphertext that decrypts to A + B — you never touched the plaintexts.</p>
        </div>

        <form id="sum-form" class="stack-form">
          <label class="field">
            <span>Message A</span>
            <input id="sum-a" inputmode="numeric" value="12" />
          </label>
          <label class="field">
            <span>Message B</span>
            <input id="sum-b" inputmode="numeric" value="30" />
          </label>
          <div class="button-row">
            <button class="button" type="submit">Encrypt A, B and multiply</button>
            <button id="overflow-preset" class="button button-ghost" type="button" disabled>Load overflow preset</button>
          </div>
          <p class="field-note" id="sum-source-note">Tip: in Step 2, hit <em>Send this ciphertext to Step 3</em> to add a ciphertext you made yourself into slot A or B.</p>
        </form>

        <div class="ledger" id="sum-ledger" hidden>
          <div class="ledger-term">
            <p class="ledger-cap"><span class="ledger-tag">Enc(A)</span> <span id="ledger-a-plain"></span></p>
            <div class="ledger-val" id="ledger-a" tabindex="0" role="region" aria-label="Ciphertext of message A"></div>
          </div>
          <div class="ledger-op" aria-hidden="true">×<span class="ledger-op-sub">mod N²</span></div>
          <div class="ledger-term">
            <p class="ledger-cap"><span class="ledger-tag">Enc(B)</span> <span id="ledger-b-plain"></span></p>
            <div class="ledger-val" id="ledger-b" tabindex="0" role="region" aria-label="Ciphertext of message B"></div>
          </div>
          <div class="ledger-op" aria-hidden="true">=</div>
          <div class="ledger-term ledger-term-product">
            <p class="ledger-cap"><span class="ledger-tag ledger-tag-product">product ciphertext</span></p>
            <div class="ledger-val" id="ledger-product" tabindex="0" role="region" aria-label="Product ciphertext, Enc(A) times Enc(B) mod N squared"></div>
          </div>
          <div class="ledger-arrow" aria-hidden="true">decrypt →</div>
          <div class="ledger-decrypt" id="ledger-decrypt"></div>
        </div>

        <div class="ledger-insight" id="sum-insight" hidden>
          <p><strong>The multiply → add mapping.</strong> The product ciphertext above is <em>not</em>
          <code id="insight-catraw">Enc(A) + Enc(B)</code> — adding the two ciphertexts as plain integers gives
          <code id="insight-badsum" class="insight-bad"></code>, which this page then actually decrypts, with the same
          private key, to <code id="insight-baddec" class="insight-bad"></code>. Only their
          <em>product mod N²</em> decrypts to A + B. Ciphertext multiplication is what maps to plaintext addition.</p>
        </div>

        <div id="sum-result" class="result-box" role="status" aria-live="polite">The decrypted result will appear here.</div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Scenario A · confidentiality</p>
            <h2>Weighted aggregation</h2>
          </div>
          <p class="section-copy">
            Hospitals submit encrypted counts and the coordinator gets a total it can never attribute. This scenario is
            about the <strong>second</strong> homomorphism: alongside the plain sum <code>∏ Enc(xᵢ)</code>, it raises each
            ciphertext to a public weight — <code>∏ Enc(xᵢ)^wᵢ</code> — so multiplication by a known constant happens
            under encryption too. (Scenario B uses the same algebra as an attack.)
          </p>
        </div>

        <form id="aggregation-form" class="stack-form">
          <label class="field">
            <span>Counts (comma separated)</span>
            <textarea id="counts-input" rows="3">10, 25, 17, 8, 30</textarea>
          </label>
          <label class="field">
            <span>Weights (optional, comma separated)</span>
            <textarea id="weights-input" rows="2">1, 2, 3, 4, 5</textarea>
          </label>
          <button class="button" type="submit">Aggregate encrypted counts</button>
        </form>

        <table class="breakdown" id="aggregation-table" hidden>
          <caption>Per-row contribution to the weighted total</caption>
          <thead>
            <tr><th scope="col">Row</th><th scope="col">Count x</th><th scope="col">Weight w</th><th scope="col">Enc(x)^w mod N² (truncated)</th></tr>
          </thead>
          <tbody id="aggregation-rows"></tbody>
        </table>

        <div id="aggregation-result" class="result-box" role="status" aria-live="polite">The encrypted total and weighted total will appear here.</div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Scenario B · integrity</p>
            <h2>Rewriting a sealed ballot</h2>
          </div>
          <p class="section-copy">
            Votes stay encrypted during collection — and that is <em>all</em> Paillier gives you. Because ciphertexts
            multiply, anyone who can touch a ballot in transit can add votes to it with the public key alone. Tally the
            ballots, then mount that attack against one of them.
          </p>
        </div>

        <form id="election-form" class="stack-form">
          <label class="field">
            <span>Votes (0 or 1, comma separated)</span>
            <textarea id="votes-input" rows="3">1, 1, 0, 1, 0, 1, 0, 1, 1, 0</textarea>
          </label>
          <button class="button" type="submit">Seal and tally ballots</button>
        </form>

        <div id="election-result" class="result-box" role="status" aria-live="polite">The encrypted tally will appear here.</div>

        <div class="attack-block" id="ballot-attack" hidden>
          <h3 class="attack-title">Malleability attack</h3>
          <p class="section-copy">
            The attacker encrypts a boost under the <strong>public</strong> key and multiplies it into someone else's
            ballot. They never see the vote and never hold <code>λ</code>. Encrypt-then-MAC is the fix: the ballot box
            re-derives each tag over the ciphertext it received and drops any that no longer match.
          </p>
          <div class="control-row">
            <label class="field compact-field">
              <span>Ballot to rewrite</span>
              <select id="attack-target"></select>
            </label>
            <label class="field compact-field">
              <span>Votes to inject</span>
              <input id="attack-boost" inputmode="numeric" value="100" />
            </label>
          </div>
          <label class="checkbox-field">
            <input type="checkbox" id="attack-authenticate" />
            <span>Ballot box verifies Encrypt-then-MAC tags</span>
          </label>
          <div class="button-row">
            <button id="forge-ballot" class="button" type="button">Forge ballot and re-tally</button>
          </div>
          <ol id="ballot-list" class="ballot-list" aria-label="Sealed ballots"></ol>
          <div id="attack-result" class="result-box" role="status" aria-live="polite">Nothing forged yet.</div>
        </div>
      </article>
    </section>

    <section class="panel panel-wide footer-panel">
      <p class="section-kicker">Verification</p>
      <p class="section-copy">
        The repo also includes a command-line verification gate that checks modular arithmetic, key generation, encryption, rerandomization, homomorphic addition, aggregation, and weighted sums.
      </p>
      <pre class="command-note">npm run verify</pre>
    </section>
  </main>
`;

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);

  if (!element) {
    throw new Error(`Missing element: ${id}`);
  }

  return element as T;
}

function parseNonNegativeBigInt(value: string, fieldName: string): bigint {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${fieldName} is required.`);
  }

  let parsed: bigint;

  try {
    parsed = BigInt(trimmed);
  } catch {
    throw new Error(`${fieldName} must be an integer.`);
  }

  if (parsed < 0n) {
    throw new Error(`${fieldName} must be non-negative.`);
  }

  return parsed;
}

function parseBigIntList(value: string, fieldName: string): bigint[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  if (parts.length === 0) {
    throw new Error(`${fieldName} must contain at least one value.`);
  }

  return parts.map((part, index) => parseNonNegativeBigInt(part, `${fieldName} #${index + 1}`));
}

function parseVoteList(value: string): number[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  if (parts.length === 0) {
    throw new Error('Votes must contain at least one entry.');
  }

  return parts.map((part, index) => {
    if (part !== '0' && part !== '1') {
      throw new Error(`Vote #${index + 1} must be 0 or 1.`);
    }

    return Number(part);
  });
}

function preview(value: bigint, edgeLength = 18): string {
  const text = value.toString();

  if (text.length <= edgeLength * 2 + 3) {
    return text;
  }

  return `${text.slice(0, edgeLength)}...${text.slice(-edgeLength)}`;
}

function setResultBox(element: HTMLElement, html: string, tone: 'neutral' | 'success' | 'error' = 'neutral'): void {
  element.dataset.tone = tone;
  element.innerHTML = html;
}

const keyForm = byId<HTMLFormElement>('key-form');
const bitLengthSelect = byId<HTMLSelectElement>('bit-length');
const generateButton = byId<HTMLButtonElement>('generate-key');
const keyStatus = byId<HTMLSpanElement>('key-status');
const keyPercent = byId<HTMLSpanElement>('key-percent');
const progressFill = byId<HTMLDivElement>('progress-fill');
const progressTrack = byId<HTMLDivElement>('progress-track');
const metricBits = byId<HTMLElement>('metric-bits');
const metricN = byId<HTMLElement>('metric-n');
const metricG = byId<HTMLElement>('metric-g');
const metricLambda = byId<HTMLElement>('metric-lambda');
const plaintextInput = byId<HTMLInputElement>('plaintext-input');
const ciphertextOutput = byId<HTMLTextAreaElement>('ciphertext-output');
const randomizerOutput = byId<HTMLTextAreaElement>('randomizer-output');
const encryptForm = byId<HTMLFormElement>('encrypt-form');
const encryptAgainButton = byId<HTMLButtonElement>('encrypt-again');
const rerandomizeButton = byId<HTMLButtonElement>('rerandomize');
const semanticDemo = byId<HTMLDivElement>('semantic-demo');
const semanticPlaintext = byId<HTMLElement>('semantic-plaintext');
const semanticList = byId<HTMLOListElement>('semantic-list');
const encryptHandoff = byId<HTMLDivElement>('encrypt-handoff');
const addToLedgerButton = byId<HTMLButtonElement>('add-to-ledger');
const handoffNote = byId<HTMLSpanElement>('handoff-note');
const decryptForm = byId<HTMLFormElement>('decrypt-form');
const decryptInput = byId<HTMLTextAreaElement>('decrypt-input');
const decryptResult = byId<HTMLDivElement>('decrypt-result');
const sumForm = byId<HTMLFormElement>('sum-form');
const sumAInput = byId<HTMLInputElement>('sum-a');
const sumBInput = byId<HTMLInputElement>('sum-b');
const overflowPresetButton = byId<HTMLButtonElement>('overflow-preset');
const sumSourceNote = byId<HTMLParagraphElement>('sum-source-note');
const sumLedger = byId<HTMLDivElement>('sum-ledger');
const ledgerAPlain = byId<HTMLElement>('ledger-a-plain');
const ledgerBPlain = byId<HTMLElement>('ledger-b-plain');
const ledgerA = byId<HTMLDivElement>('ledger-a');
const ledgerB = byId<HTMLDivElement>('ledger-b');
const ledgerProduct = byId<HTMLDivElement>('ledger-product');
const ledgerDecrypt = byId<HTMLDivElement>('ledger-decrypt');
const sumInsight = byId<HTMLDivElement>('sum-insight');
const insightBadSum = byId<HTMLElement>('insight-badsum');
const insightBadDecrypt = byId<HTMLElement>('insight-baddec');
const sumResult = byId<HTMLDivElement>('sum-result');
const aggregationForm = byId<HTMLFormElement>('aggregation-form');
const countsInput = byId<HTMLTextAreaElement>('counts-input');
const weightsInput = byId<HTMLTextAreaElement>('weights-input');
const aggregationResult = byId<HTMLDivElement>('aggregation-result');
const aggregationTable = byId<HTMLTableElement>('aggregation-table');
const aggregationRows = byId<HTMLTableSectionElement>('aggregation-rows');
const electionForm = byId<HTMLFormElement>('election-form');
const votesInput = byId<HTMLTextAreaElement>('votes-input');
const electionResult = byId<HTMLDivElement>('election-result');
const factorButton = byId<HTMLButtonElement>('factor-key');
const factorBudgetLabel = byId<HTMLElement>('factor-budget');
const factorResult = byId<HTMLDivElement>('factor-result');
const stepDecryptButton = byId<HTMLButtonElement>('step-decrypt');
const resetStepperButton = byId<HTMLButtonElement>('reset-stepper');
const stepperList = byId<HTMLOListElement>('stepper-list');
const ballotAttack = byId<HTMLDivElement>('ballot-attack');
const attackTarget = byId<HTMLSelectElement>('attack-target');
const attackBoost = byId<HTMLInputElement>('attack-boost');
const attackAuthenticate = byId<HTMLInputElement>('attack-authenticate');
const forgeButton = byId<HTMLButtonElement>('forge-ballot');
const ballotList = byId<HTMLOListElement>('ballot-list');
const attackResult = byId<HTMLDivElement>('attack-result');

const requiresKeyControls = Array.from(
  app.querySelectorAll<HTMLButtonElement>('button:not(#generate-key)'),
);

const keygenWorker = new Worker(new URL('./keygen.worker.ts', import.meta.url), { type: 'module' });

let activeKeyPair: PaillierKeyPair | null = null;
let isGenerating = false;

// The most recent single-message ciphertext the learner produced in Step 2,
// plus the message it encrypts. This is what the "send to Step 3" hand-off
// pushes into a slot so the learner combines a ciphertext they made rather than
// one the demo re-encrypts behind their back.
let lastEncryption: { message: bigint; ciphertext: bigint } | null = null;
let semanticMessage: bigint | null = null;

// Ciphertexts sitting in Step 3's A/B slots. `null` means "encrypt this input
// fresh on submit"; a bigint means "reuse this exact ciphertext the learner
// handed off from Step 2."
const suppliedCiphertext: { a: bigint | null; b: bigint | null } = { a: null, b: null };

// Decryption-stepper state: the ciphertext being walked, the precomputed real
// steps for it, and how many have been revealed.
let stepperTrace: { ciphertext: bigint; steps: DecryptionStep[]; revealed: number } | null = null;

// Election state for the malleability exhibit.
let ballotState: {
  key: CryptoKey;
  ballots: SealedBallot[];
  honestTally: bigint;
  honestSum: bigint;
} | null = null;

let isFactoring = false;

function updateControlState(): void {
  generateButton.disabled = isGenerating;
  generateButton.setAttribute('aria-busy', String(isGenerating));
  progressTrack.setAttribute('aria-busy', String(isGenerating));

  for (const control of requiresKeyControls) {
    control.disabled = !activeKeyPair || isGenerating;
  }

  // "Encrypt again" also needs a prior encryption to repeat, and re-randomizing
  // needs an existing ciphertext to refresh.
  encryptAgainButton.disabled = !activeKeyPair || isGenerating || semanticMessage === null;
  rerandomizeButton.disabled = !activeKeyPair || isGenerating || lastEncryption === null;
  factorButton.disabled = !activeKeyPair || isGenerating || isFactoring;
  factorButton.setAttribute('aria-busy', String(isFactoring));
  // Nothing left to step once the trace for the ciphertext currently in the box
  // has been fully revealed; editing the box starts a new trace.
  const traceExhausted = stepperTrace !== null
    && stepperTrace.revealed >= stepperTrace.steps.length
    && stepperTrace.ciphertext.toString() === decryptInput.value.trim();
  stepDecryptButton.disabled = !activeKeyPair || isGenerating
    || decryptInput.value.trim() === '' || traceExhausted;
  resetStepperButton.disabled = stepperTrace === null;
  forgeButton.disabled = !activeKeyPair || isGenerating || ballotState === null;
}

function setProgress(stage: string, percent: number): void {
  const clamped = Math.max(0, Math.min(100, percent));
  keyStatus.textContent = stage;
  keyPercent.textContent = `${Math.round(clamped)}%`;
  progressFill.style.width = `${clamped}%`;
  progressTrack.setAttribute('aria-valuenow', `${Math.round(clamped)}`);
}

function renderKeyPair(keyPair: PaillierKeyPair): void {
  metricBits.textContent = `${keyPair.publicKey.bitLength}`;
  metricN.textContent = preview(keyPair.publicKey.N);
  metricG.textContent = preview(keyPair.publicKey.g);
  metricLambda.textContent = preview(keyPair.privateKey.lambda);
}

function requireKeyPair(): PaillierKeyPair {
  if (!activeKeyPair) {
    throw new Error('Generate a keypair first.');
  }

  return activeKeyPair;
}

keygenWorker.addEventListener('message', (event: MessageEvent<WorkerMessage>) => {
  const message = event.data;

  if (message.type === 'progress') {
    setProgress(message.stage, message.percent);
    return;
  }

  isGenerating = false;
  updateControlState();

  if (message.type === 'success') {
    activeKeyPair = message.keyPair;
    renderKeyPair(message.keyPair);
    setProgress('Keypair ready. The playground is unlocked.', 100);
    setResultBox(decryptResult, 'Paste any ciphertext from this page into the decrypt box, then decode it here.', 'success');
    setResultBox(sumResult, 'Multiply two ciphertexts and compare the decrypted product with the plaintext sum.', 'success');
    // A fresh keypair invalidates every ciphertext on the page.
    resetSemanticDemo();
    resetHandoff();
    resetLedger();
    resetStepper();
    resetBallots();
    setResultBox(factorResult, 'Key is fresh. Try to factor N and rebuild λ from it.', 'success');
    setResultBox(aggregationResult, 'Run a hospital-style aggregation or weighted total with the new keypair.', 'success');
    setResultBox(electionResult, 'Run an encrypted binary vote tally with the new keypair.', 'success');
    updateControlState();
    return;
  }

  setProgress(message.message, 0);
  setResultBox(decryptResult, message.message, 'error');
});

keyForm.addEventListener('submit', (event) => {
  event.preventDefault();

  if (isGenerating) {
    return;
  }

  activeKeyPair = null;
  isGenerating = true;
  updateControlState();
  renderKeyPair({
    publicKey: { N: 0n, g: 0n, N2: 0n, bitLength: 0 },
    privateKey: { lambda: 0n, mu: 0n, p: 0n, q: 0n },
  });
  metricN.textContent = 'Generating...';
  metricG.textContent = 'Generating...';
  metricLambda.textContent = 'Generating...';
  ciphertextOutput.value = '';
  randomizerOutput.value = '';
  decryptInput.value = '';
  resetSemanticDemo();
  resetHandoff();
  resetLedger();
  resetStepper();
  resetBallots();
  setProgress('Dispatching key generation worker...', 2);

  const request: GenerateRequest = {
    type: 'generate',
    bitLength: Number(bitLengthSelect.value),
  };

  keygenWorker.postMessage(request);
});

function resetSemanticDemo(): void {
  semanticMessage = null;
  semanticList.innerHTML = '';
  semanticDemo.hidden = true;
}

function resetHandoff(): void {
  lastEncryption = null;
  encryptHandoff.hidden = true;
  handoffNote.textContent = '';
}

// Append one ciphertext row to the "same message, different ciphertext" stack.
// The row's caption is the result of actually decrypting that ciphertext with
// the private key, so the "they all decrypt to the same m" claim on this panel
// is computed per row rather than asserted.
function addSemanticRow(ciphertext: bigint, origin: 'encrypted' | 're-randomized'): void {
  const keyPair = requireKeyPair();
  const item = document.createElement('li');
  const code = document.createElement('code');
  code.className = 'semantic-ct';
  code.tabIndex = 0;
  code.setAttribute('role', 'region');
  code.setAttribute('aria-label', `Ciphertext ${semanticList.children.length + 1} of the same plaintext`);
  code.textContent = ciphertext.toString();
  item.appendChild(code);

  const note = document.createElement('span');
  note.className = 'field-note';

  let recovered: string;

  try {
    recovered = decrypt(ciphertext, keyPair).toString();
  } catch (error) {
    recovered = error instanceof Error ? `did not decrypt (${error.message})` : 'did not decrypt';
  }

  note.textContent = ` ${origin} · decrypts to ${recovered}`;
  item.appendChild(note);
  semanticList.appendChild(item);
}

function doEncrypt(message: bigint, isRepeat: boolean): void {
  const keyPair = requireKeyPair();
  const encrypted = encrypt(message, keyPair.publicKey);

  ciphertextOutput.value = encrypted.ciphertext.toString();
  randomizerOutput.value = encrypted.r.toString();
  decryptInput.value = encrypted.ciphertext.toString();

  // Track the freshest single-message ciphertext for the Step 3 hand-off.
  lastEncryption = { message, ciphertext: encrypted.ciphertext };
  encryptHandoff.hidden = false;
  handoffNote.textContent = `Ready to hand off Enc(${message.toString()}).`;

  // Maintain the semantic-security stack. Changing the message starts a new one.
  if (!isRepeat || semanticMessage !== message) {
    semanticMessage = message;
    semanticList.innerHTML = '';
  }
  semanticPlaintext.textContent = message.toString();
  addSemanticRow(encrypted.ciphertext, 'encrypted');
  semanticDemo.hidden = false;

  const count = semanticList.children.length;
  setResultBox(
    decryptResult,
    `Ciphertext generated for plaintext <strong>${message.toString()}</strong>. `
      + (count > 1
        ? `You now have <strong>${count}</strong> different ciphertexts of the same message stacked below — all decrypt to ${message.toString()}.`
        : 'Decrypt it below, or press <em>Encrypt again</em> to watch fresh randomness produce a different ciphertext.'),
    'success',
  );
  updateControlState();
}

encryptForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const message = parseNonNegativeBigInt(plaintextInput.value, 'Plaintext');
    doEncrypt(message, false);
  } catch (error) {
    setResultBox(decryptResult, error instanceof Error ? error.message : 'Encryption failed.', 'error');
  }
});

encryptAgainButton.addEventListener('click', () => {
  if (semanticMessage === null) {
    return;
  }

  try {
    doEncrypt(semanticMessage, true);
  } catch (error) {
    setResultBox(decryptResult, error instanceof Error ? error.message : 'Encryption failed.', 'error');
  }
});

// Re-randomization: multiply the existing ciphertext by a fresh r^N, which
// changes every digit of the ciphertext while leaving the plaintext untouched.
// It needs only the public key — the page never re-encrypts m here.
rerandomizeButton.addEventListener('click', () => {
  if (!lastEncryption) {
    return;
  }

  try {
    const keyPair = requireKeyPair();
    const refreshed = rerandomize(lastEncryption.ciphertext, keyPair.publicKey);
    const changed = refreshed !== lastEncryption.ciphertext;

    lastEncryption = { message: lastEncryption.message, ciphertext: refreshed };
    ciphertextOutput.value = refreshed.toString();
    randomizerOutput.value = 'r is now r_old · r_new mod N — the page multiplies in a fresh factor and does not track the product';
    decryptInput.value = refreshed.toString();
    handoffNote.textContent = `Ready to hand off Enc(${lastEncryption.message.toString()}).`;

    semanticMessage = lastEncryption.message;
    semanticPlaintext.textContent = lastEncryption.message.toString();
    addSemanticRow(refreshed, 're-randomized');
    semanticDemo.hidden = false;

    setResultBox(
      decryptResult,
      changed
        ? 'Re-randomized with the <strong>public key only</strong>: the ciphertext changed, and the row added below '
          + 'shows what it decrypts to now.'
        : 'Re-randomization returned the same ciphertext — the fresh factor happened to be 1. Press it again.',
      changed ? 'success' : 'error',
    );
    updateControlState();
  } catch (error) {
    setResultBox(decryptResult, error instanceof Error ? error.message : 'Re-randomization failed.', 'error');
  }
});

// Hand the learner's own ciphertext to Step 3. Fills slot A first, then B, so
// two consecutive hand-offs populate both operands the learner created.
addToLedgerButton.addEventListener('click', () => {
  if (!lastEncryption) {
    return;
  }

  const slot: 'a' | 'b' = suppliedCiphertext.a === null ? 'a' : 'b';
  suppliedCiphertext[slot] = lastEncryption.ciphertext;

  if (slot === 'a') {
    sumAInput.value = lastEncryption.message.toString();
    sumAInput.readOnly = true;
    sumAInput.classList.add('slot-locked');
  } else {
    sumBInput.value = lastEncryption.message.toString();
    sumBInput.readOnly = true;
    sumBInput.classList.add('slot-locked');
  }

  const filled: string[] = [];
  if (suppliedCiphertext.a !== null) filled.push('A');
  if (suppliedCiphertext.b !== null) filled.push('B');
  sumSourceNote.innerHTML = `Slot ${filled.join(' and ')} now hold${filled.length > 1 ? '' : 's'} `
    + `a ciphertext <strong>you</strong> made in Step 2 (locked). `
    + `${filled.length < 2 ? 'Send one more, or edit the other field to encrypt it fresh. ' : ''}`
    + 'Press <em>Encrypt A, B and multiply</em> to combine them. '
    + '<button type="button" id="clear-slots" class="link-button">Clear slots</button>';

  const clearButton = document.getElementById('clear-slots');
  clearButton?.addEventListener('click', clearSlots);

  handoffNote.textContent = `Sent Enc(${lastEncryption.message.toString()}) to slot ${slot.toUpperCase()}.`;
});

function clearSlots(): void {
  suppliedCiphertext.a = null;
  suppliedCiphertext.b = null;
  sumAInput.readOnly = false;
  sumBInput.readOnly = false;
  sumAInput.classList.remove('slot-locked');
  sumBInput.classList.remove('slot-locked');
  sumSourceNote.innerHTML = 'Tip: in Step 2, hit <em>Send this ciphertext to Step 3</em> to add a ciphertext you made yourself into slot A or B.';
}

decryptForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const ciphertext = parseNonNegativeBigInt(decryptInput.value, 'Ciphertext');
    const plaintext = decrypt(ciphertext, keyPair);

    setResultBox(
      decryptResult,
      `Decrypted value: <strong>${plaintext.toString()}</strong>`,
      'success',
    );
  } catch (error) {
    setResultBox(decryptResult, error instanceof Error ? error.message : 'Decryption failed.', 'error');
  }
});

function resetLedger(): void {
  sumLedger.hidden = true;
  sumInsight.hidden = true;
  ledgerA.textContent = '';
  ledgerB.textContent = '';
  ledgerProduct.textContent = '';
  ledgerDecrypt.textContent = '';
  ledgerAPlain.textContent = '';
  ledgerBPlain.textContent = '';
  insightBadSum.textContent = '';
  insightBadDecrypt.textContent = '';
  clearSlots();
}

sumForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const { N } = keyPair.publicKey;
    const left = parseNonNegativeBigInt(sumAInput.value, 'Message A');
    const right = parseNonNegativeBigInt(sumBInput.value, 'Message B');

    // Reuse the exact ciphertext the learner handed off from Step 2 when a slot
    // is supplied; otherwise encrypt the field value fresh. Either way these are
    // real ciphertexts we multiply — nothing is faked.
    const cA = suppliedCiphertext.a ?? encrypt(left, keyPair.publicKey).ciphertext;
    const cB = suppliedCiphertext.b ?? encrypt(right, keyPair.publicKey).ciphertext;

    const product = addCiphertexts(cA, cB, keyPair.publicKey);
    const decryptedTotal = decrypt(product, keyPair);
    const plainSum = left + right;
    const overflowed = plainSum >= N;

    // Populate the visible homomorphic-addition ledger with full values.
    ledgerAPlain.textContent = suppliedCiphertext.a !== null ? `= Enc(${left}) — yours` : `= Enc(${left})`;
    ledgerBPlain.textContent = suppliedCiphertext.b !== null ? `= Enc(${right}) — yours` : `= Enc(${right})`;
    ledgerA.textContent = cA.toString();
    ledgerB.textContent = cB.toString();
    ledgerProduct.textContent = product.toString();
    ledgerDecrypt.innerHTML = overflowed
      ? `<strong class="ledger-wrong">${decryptedTotal.toString()}</strong> `
        + `<span class="ledger-decrypt-note">(A + B = ${plainSum.toString()} ≥ N, so it wrapped)</span>`
      : `<strong>${left} + ${right} = ${decryptedTotal.toString()}</strong>`;
    sumLedger.hidden = false;

    // Show that ciphertext-multiply — not ciphertext-add — is what maps to
    // plaintext-add: adding the two ciphertexts as integers gives a different,
    // wrong value. (Reduced mod N² since ciphertexts live in that ring.)
    const naiveSum = (cA + cB) % keyPair.publicKey.N2;
    insightBadSum.textContent = preview(naiveSum);

    // Decrypt the integer sum for real rather than asserting it is garbage. It
    // is only a valid ciphertext when it happens to be a unit mod N, so a
    // failure to decrypt at all is also a legitimate outcome to report.
    let naiveDecryption: string;

    try {
      const naivePlaintext = decrypt(naiveSum, keyPair);
      naiveDecryption = naivePlaintext === plainSum % N
        ? `${preview(naivePlaintext)} (a coincidence at this key size — regenerate a larger key)`
        : preview(naivePlaintext);
    } catch {
      naiveDecryption = 'nothing at all — it is not even a valid ciphertext';
    }

    insightBadDecrypt.textContent = naiveDecryption;
    sumInsight.hidden = false;

    if (overflowed) {
      setResultBox(
        sumResult,
        [
          `<strong>Modulus overflow.</strong> The true plaintext sum is <strong>${plainSum.toString()}</strong>, `
            + `but that is ≥ N (${preview(N)}).`,
          `The product ciphertext decrypts to <strong>${decryptedTotal.toString()}</strong> — i.e. `
            + `(A + B) mod N. Paillier's plaintext space is the integers mod N; a sum that exceeds N wraps and the `
            + `decryption is silently wrong. Real deployments bound inputs so the running total can never reach N.`,
        ].join('<br /><br />'),
        'error',
      );
    } else {
      setResultBox(
        sumResult,
        [
          `The product ciphertext decrypts to <strong>${decryptedTotal.toString()}</strong>, exactly `
            + `A + B = ${left} + ${right}.`,
          `You added two encrypted numbers without ever decrypting them individually. `
            + `The sum stays below N (${preview(N)}), so no wrap-around.`,
        ].join('<br /><br />'),
        'success',
      );
    }
  } catch (error) {
    setResultBox(sumResult, error instanceof Error ? error.message : 'Encrypted sum failed.', 'error');
  }
});

// Load values whose sum exceeds N so the learner can watch decryption wrap. We
// use N so both operands are legal plaintexts (each < N) yet their sum is >= N.
overflowPresetButton.addEventListener('click', () => {
  try {
    const { N } = requireKeyPair().publicKey;
    clearSlots();
    // Two in-range plaintexts (< N) whose sum lands just past N.
    const a = N - 5n;
    const b = 10n;
    sumAInput.value = a.toString();
    sumBInput.value = b.toString();
    sumSourceNote.innerHTML = 'Overflow preset loaded: A + B exceeds N. '
      + 'Press <em>Encrypt A, B and multiply</em> to watch the decryption wrap around.';
  } catch (error) {
    setResultBox(sumResult, error instanceof Error ? error.message : 'Preset failed.', 'error');
  }
});

aggregationForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const counts = parseBigIntList(countsInput.value, 'Counts');
    const weights = parseBigIntList(weightsInput.value, 'Weights');
    const scenario = simulatePrivateAggregation(counts, keyPair.publicKey);
    const decryptedTotal = decrypt(scenario.encryptedTotal, keyPair);
    const weightedCiphertext = weightedSum(
      scenario.hospitals.map((hospital) => hospital.encryptedCount),
      weights,
      keyPair.publicKey,
    );
    const decryptedWeighted = decrypt(weightedCiphertext, keyPair);
    // Per-row breakdown: the weighted contribution is Enc(x)^w mod N², a real
    // ciphertext exponentiation, printed next to the numbers that produced it.
    aggregationRows.innerHTML = '';
    scenario.hospitals.forEach((hospital, index) => {
      const weight = weights[index] ?? 1n;
      const contribution = multiplyByScalar(hospital.encryptedCount, weight, keyPair.publicKey);
      const row = document.createElement('tr');
      for (const text of [
        hospital.id,
        hospital.privateCount.toString(),
        weight.toString(),
        preview(contribution, 10),
      ]) {
        const cell = document.createElement('td');
        cell.textContent = text;
        row.appendChild(cell);
      }
      aggregationRows.appendChild(row);
    });
    aggregationTable.hidden = false;

    // Both totals are checked against the arithmetic they claim to perform.
    const plainTotal = counts.reduce((sum, value) => sum + value, 0n);
    const plainWeighted = counts.reduce(
      (sum, value, index) => sum + value * (weights[index] ?? 1n),
      0n,
    );

    setResultBox(
      aggregationResult,
      [
        `Sum ∏ Enc(xᵢ) decrypts to <strong>${decryptedTotal.toString()}</strong> `
          + `(plaintext Σxᵢ = ${plainTotal.toString()} — ${decryptedTotal === plainTotal % keyPair.publicKey.N ? 'match' : 'mismatch'}).`,
        `Weighted ∏ Enc(xᵢ)<sup>wᵢ</sup> decrypts to <strong>${decryptedWeighted.toString()}</strong> `
          + `(plaintext Σwᵢxᵢ = ${plainWeighted.toString()} — ${decryptedWeighted === plainWeighted % keyPair.publicKey.N ? 'match' : 'mismatch'}).`,
        `Exponentiating a ciphertext by a public constant is the second homomorphism: it multiplies the hidden `
          + `plaintext without revealing it. Scenario B turns that same move into an attack.`,
      ].join('<br /><br />'),
      'success',
    );
  } catch (error) {
    setResultBox(aggregationResult, error instanceof Error ? error.message : 'Aggregation failed.', 'error');
  }
});

function resetBallots(): void {
  ballotState = null;
  ballotAttack.hidden = true;
  ballotList.innerHTML = '';
  attackTarget.innerHTML = '';
  setResultBox(attackResult, 'Nothing forged yet.', 'neutral');
}

// Render the ballot box's current contents: the ciphertext each voter submitted,
// the tag that was sealed with it, and whether it still matches.
function renderBallots(ballots: SealedBallot[]): void {
  ballotList.innerHTML = '';

  for (const ballot of ballots) {
    const item = document.createElement('li');
    item.className = ballot.tampered ? 'ballot-row ballot-row-tampered' : 'ballot-row';

    const who = document.createElement('span');
    who.className = 'ballot-who';
    who.textContent = ballot.voterId + (ballot.tampered ? ' — rewritten in transit' : '');
    item.appendChild(who);

    const code = document.createElement('code');
    code.className = 'ballot-ct';
    code.textContent = preview(ballot.ciphertext, 14);
    item.appendChild(code);

    const tag = document.createElement('span');
    tag.className = 'field-note';
    tag.textContent = ` tag ${ballot.tag.slice(0, 16)}…`;
    item.appendChild(tag);

    ballotList.appendChild(item);
  }
}

electionForm.addEventListener('submit', (event) => {
  event.preventDefault();

  void (async () => {
    try {
      const keyPair = requireKeyPair();
      const votes = parseVoteList(votesInput.value);
      const key = await generateBallotKey();
      const ballots = await sealBallots(votes, keyPair.publicKey, key);
      const encryptedTally = ballots.reduce(
        (accumulator, ballot) => addCiphertexts(accumulator, ballot.ciphertext, keyPair.publicKey),
        1n,
      );
      const decryptedTally = decrypt(encryptedTally, keyPair);
      const honestSum = BigInt(votes.reduce((sum, vote) => sum + vote, 0));

      ballotState = { key, ballots, honestTally: decryptedTally, honestSum };

      attackTarget.innerHTML = '';
      ballots.forEach((ballot, index) => {
        const option = document.createElement('option');
        option.value = String(index);
        option.textContent = ballot.voterId;
        attackTarget.appendChild(option);
      });

      renderBallots(ballots);
      ballotAttack.hidden = false;
      setResultBox(attackResult, 'Nothing forged yet.', 'neutral');

      setResultBox(
        electionResult,
        [
          `Sealed <strong>${ballots.length}</strong> ballots, each encrypted under the public key and tagged with `
            + `HMAC-SHA256 by the ballot box.`,
          `Honest tally decrypts to <strong>${decryptedTally.toString()} / ${votes.length}</strong> `
            + `(your 0/1 inputs sum to ${honestSum.toString()} — `
            + `${decryptedTally === honestSum ? 'match' : 'mismatch'}).`,
        ].join('<br /><br />'),
        'success',
      );
      updateControlState();
    } catch (error) {
      setResultBox(electionResult, error instanceof Error ? error.message : 'Election tally failed.', 'error');
    }
  })();
});

// The attack itself. Everything the attacker does here goes through
// forgeBallot(), which only ever receives the public key.
forgeButton.addEventListener('click', () => {
  void (async () => {
    if (!ballotState) {
      return;
    }

    try {
      const keyPair = requireKeyPair();
      const index = Number(attackTarget.value);
      const target = ballotState.ballots[index];

      if (!target) {
        throw new Error('Pick a ballot to rewrite.');
      }

      const boost = parseNonNegativeBigInt(attackBoost.value, 'Votes to inject');
      const forged = forgeBallot(target.ciphertext, boost, keyPair.publicKey);

      // Replace the ciphertext in transit. The stored tag is left alone — the
      // attacker cannot recompute it without the ballot box's MAC key.
      ballotState.ballots[index] = { ...target, ciphertext: forged.forgedCiphertext, tampered: true };
      renderBallots(ballotState.ballots);

      const authenticate = attackAuthenticate.checked;
      const box = await runBallotBox(
        ballotState.ballots,
        keyPair.publicKey,
        ballotState.key,
        authenticate,
      );
      const newTally = decrypt(box.encryptedTally, keyPair);
      const recomputedTag = await tagCiphertext(forged.forgedCiphertext, ballotState.key);
      const delta = newTally - ballotState.honestTally;

      const attackLine = `Attacker computed Enc(${boost.toString()}) = <code>${preview(forged.injectedCiphertext, 10)}</code> `
        + `with the public key and multiplied it into ${target.voterId}'s ballot mod N². They still do not know how `
        + `${target.voterId} voted.`;

      if (authenticate) {
        setResultBox(
          attackResult,
          [
            attackLine,
            `<strong>Encrypt-then-MAC caught it.</strong> The ballot box recomputed the tag over the ciphertext it `
              + `received: <code>${recomputedTag.slice(0, 24)}…</code> ≠ sealed <code>${target.tag.slice(0, 24)}…</code>. `
              + `${box.rejected.length} ballot(s) rejected, ${box.accepted.length} counted.`,
            `Tally over the accepted ballots decrypts to <strong>${newTally.toString()}</strong> — the rigged +${boost.toString()} `
              + `never landed. It is below the honest ${ballotState.honestTally.toString()} because the rejected ballot's own `
              + `vote was dropped with it; authentication stops forgery, it does not repair a lost ballot.`,
          ].join('<br /><br />'),
          'success',
        );
      } else {
        setResultBox(
          attackResult,
          [
            attackLine,
            `<strong>The tally is rigged.</strong> It now decrypts to <strong>${newTally.toString()}</strong>, `
              + `${delta >= 0n ? '+' : ''}${delta.toString()} against the honest ${ballotState.honestTally.toString()}. `
              + `The ballot box accepted all ${box.accepted.length} ballots because it checked nothing.`,
            `Additive homomorphism <em>is</em> malleability. Turn on the tag check above and run the same attack again.`,
          ].join('<br /><br />'),
          'error',
        );
      }
    } catch (error) {
      setResultBox(attackResult, error instanceof Error ? error.message : 'Forgery failed.', 'error');
    }
  })();
});

// ---------------------------------------------------------------------------
// Decryption stepper: execute m = L(c^λ mod N²) · μ mod N one operation at a
// time on whatever ciphertext is currently in the decrypt box.
// ---------------------------------------------------------------------------

function resetStepper(): void {
  stepperTrace = null;
  stepperList.innerHTML = '';
  updateControlState();
}

stepDecryptButton.addEventListener('click', () => {
  try {
    const keyPair = requireKeyPair();
    const ciphertext = parseNonNegativeBigInt(decryptInput.value, 'Ciphertext');

    if (!stepperTrace || stepperTrace.ciphertext !== ciphertext) {
      stepperList.innerHTML = '';
      stepperTrace = { ciphertext, steps: traceDecryption(ciphertext, keyPair), revealed: 0 };
    }

    if (stepperTrace.revealed >= stepperTrace.steps.length) {
      return;
    }

    const step = stepperTrace.steps[stepperTrace.revealed];
    stepperTrace.revealed += 1;
    const isLast = stepperTrace.revealed === stepperTrace.steps.length;

    const item = document.createElement('li');
    item.className = isLast ? 'stepper-item stepper-item-final' : 'stepper-item';

    const label = document.createElement('p');
    label.className = 'stepper-label';
    label.textContent = step.label;
    item.appendChild(label);

    const expression = document.createElement('code');
    expression.className = 'stepper-expr';
    expression.textContent = step.expression;
    item.appendChild(expression);

    const value = document.createElement('code');
    value.className = 'stepper-value';
    value.tabIndex = 0;
    value.setAttribute('role', 'region');
    value.setAttribute('aria-label', `Value after step ${stepperTrace.revealed}`);
    value.textContent = step.value.toString();
    item.appendChild(value);

    if (isLast) {
      // Cross-check the hand-walked identity against the library decrypt().
      const viaDecrypt = decrypt(ciphertext, keyPair);
      const note = document.createElement('p');
      note.className = 'stepper-note';
      note.textContent = `decrypt() returns ${viaDecrypt.toString()} for the same ciphertext — `
        + `${viaDecrypt === step.value ? 'the stepped identity agrees' : 'MISMATCH'}.`;
      item.appendChild(note);
    }

    stepperList.appendChild(item);
    updateControlState();
  } catch (error) {
    const item = document.createElement('li');
    item.className = 'stepper-item';
    item.textContent = error instanceof Error ? error.message : 'Stepping failed.';
    stepperList.appendChild(item);
  }
});

resetStepperButton.addEventListener('click', resetStepper);

// ---------------------------------------------------------------------------
// Factoring: the real break. Pollard rho in a worker, with the step count and
// wall-clock time it actually used reported either way.
// ---------------------------------------------------------------------------

factorBudgetLabel.textContent = DEFAULT_BUDGET.toLocaleString('en-US');

const factorWorker = new Worker(new URL('./factor.worker.ts', import.meta.url), { type: 'module' });

factorWorker.addEventListener('message', (event: MessageEvent<FactorWorkerMessage>) => {
  const message = event.data;

  if (message.type === 'progress') {
    setResultBox(
      factorResult,
      `Searching… ${message.iterations.toLocaleString('en-US')} modular squarings so far.`,
      'neutral',
    );
    return;
  }

  isFactoring = false;
  updateControlState();

  if (message.type === 'error') {
    setResultBox(factorResult, message.message, 'error');
    return;
  }

  const { factor, iterations, ms, gaveUp } = message.result;

  try {
    const keyPair = requireKeyPair();
    const bits = keyPair.publicKey.bitLength;
    const expected = expectedIterations(bits);
    const rate = ms > 0 ? Math.round(iterations / (ms / 1000)) : iterations;

    if (!factor || gaveUp) {
      setResultBox(
        factorResult,
        [
          `<strong>Gave up.</strong> ${iterations.toLocaleString('en-US')} modular squarings in ${ms} ms `
            + `(~${rate.toLocaleString('en-US')}/s) did not split this ${bits}-bit N.`,
          `Pollard rho needs about 1.18·√p ≈ <strong>${Math.round(expected).toLocaleString('en-US')}</strong> steps for a `
            + `${Math.floor(bits / 2)}-bit prime, and the budget here is ${DEFAULT_BUDGET.toLocaleString('en-US')}. `
            + `Drop to 64-bit and the same code finishes instantly. Every extra 4 bits of N doubles that expected work — `
            + `which is the entire argument for 2048-bit moduli, at which √p is around 2<sup>512</sup>.`,
        ].join('<br /><br />'),
        'error',
      );
      return;
    }

    const recovered = recoverPrivateKey(keyPair.publicKey, factor);
    const matches = recovered.lambda === keyPair.privateKey.lambda;
    const attackerKeyPair = keyPairFromRecovered(keyPair.publicKey, recovered);

    let plaintextLine = 'Encrypt something in Step 2 and factor again to watch the recovered key open it.';

    if (lastEncryption) {
      const stolen = decrypt(lastEncryption.ciphertext, attackerKeyPair);
      plaintextLine = `Decrypting your Step 2 ciphertext with the <em>recovered</em> key yields `
        + `<strong>${stolen.toString()}</strong> — you encrypted ${lastEncryption.message.toString()} `
        + `(${stolen === lastEncryption.message ? 'the key is broken' : 'no match'}).`;
    }

    setResultBox(
      factorResult,
      [
        `<strong>Factored.</strong> ${iterations.toLocaleString('en-US')} modular squarings in ${ms} ms `
          + `(~${rate.toLocaleString('en-US')}/s) split the ${bits}-bit modulus.`,
        `p = <code>${recovered.p.toString()}</code><br />q = <code>${recovered.q.toString()}</code>`,
        `Rebuilt λ = lcm(p−1, q−1) = <code>${preview(recovered.lambda)}</code> — `
          + `${matches ? 'identical to the private λ generated in the worker' : 'does not match the generated λ'}.`,
        plaintextLine,
      ].join('<br /><br />'),
      'error',
    );
  } catch (error) {
    setResultBox(factorResult, error instanceof Error ? error.message : 'Recovery failed.', 'error');
  }
});

factorButton.addEventListener('click', () => {
  try {
    const keyPair = requireKeyPair();
    isFactoring = true;
    updateControlState();
    setResultBox(factorResult, 'Running Pollard rho against N…', 'neutral');
    factorWorker.postMessage({ type: 'factor', N: keyPair.publicKey.N, budget: DEFAULT_BUDGET });
  } catch (error) {
    isFactoring = false;
    updateControlState();
    setResultBox(factorResult, error instanceof Error ? error.message : 'Factoring failed.', 'error');
  }
});

// The stepper only makes sense once there is a ciphertext to walk.
decryptInput.addEventListener('input', updateControlState);

updateControlState();