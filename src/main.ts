import {
  addCiphertexts,
  decrypt,
  encrypt,
  type PaillierKeyPair,
} from './paillier';
import { simulatePrivateAggregation, simulatePrivateElection, weightedSum } from './aggregation';
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

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found.');
}

app.innerHTML = `
  <main class="shell">
    <header class="masthead panel panel-wide">
      <button
        id="theme-toggle"
        class="theme-toggle"
        type="button"
        aria-label="Switch to light mode"
        style="position: absolute; top: 0; right: 0"
      >🌙</button>
      <div>
        <p class="eyebrow">crypto-lab / browser demo</p>
        <h1>Paillier Gate</h1>
        <p class="lede">
          Generate a toy Paillier keypair in the browser, encrypt values, and verify that addition works on ciphertexts before decryption.
        </p>
      </div>
      <div class="callout">
        <span class="callout-label">Why this matters</span>
        <p>
          An aggregator can combine encrypted totals without seeing the private inputs. The final tally is revealed only after decryption.
        </p>
      </div>
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
          <span id="key-status">No keypair loaded.</span>
          <span id="key-percent">0%</span>
        </div>
        <div class="progress-track"><div id="progress-fill" class="progress-fill"></div></div>
      </div>

      <div class="key-grid">
        <article class="metric-card">
          <span class="metric-label">Modulus bits</span>
          <strong id="metric-bits">-</strong>
        </article>
        <article class="metric-card">
          <span class="metric-label">Public modulus N</span>
          <code id="metric-n">Generate a keypair to populate this field.</code>
        </article>
        <article class="metric-card">
          <span class="metric-label">Generator g</span>
          <code id="metric-g">-</code>
        </article>
        <article class="metric-card">
          <span class="metric-label">Private λ</span>
          <code id="metric-lambda">-</code>
        </article>
      </div>
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
          <button class="button" type="submit">Encrypt message</button>
        </form>

        <div class="output-stack">
          <label class="field">
            <span>Ciphertext</span>
            <textarea id="ciphertext-output" readonly rows="4"></textarea>
          </label>
          <label class="field">
            <span>Randomizer r</span>
            <textarea id="randomizer-output" readonly rows="2"></textarea>
          </label>
        </div>

        <form id="decrypt-form" class="stack-form">
          <label class="field">
            <span>Ciphertext to decrypt</span>
            <textarea id="decrypt-input" rows="4"></textarea>
          </label>
          <button class="button" type="submit">Decrypt ciphertext</button>
        </form>

        <div id="decrypt-result" class="result-box">Generate a keypair first.</div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Step 3</p>
            <h2>Homomorphic addition</h2>
          </div>
          <p class="section-copy">Encrypt two messages, multiply their ciphertexts modulo $N^2$, then decrypt the result.</p>
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
          <button class="button" type="submit">Compute encrypted sum</button>
        </form>

        <div class="output-stack">
          <label class="field">
            <span>Encrypted sum</span>
            <textarea id="sum-ciphertext" readonly rows="4"></textarea>
          </label>
        </div>

        <div id="sum-result" class="result-box">The decrypted result will appear here.</div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Scenario A</p>
            <h2>Private aggregation</h2>
          </div>
          <p class="section-copy">Hospitals submit encrypted counts. The coordinator receives a total without seeing the raw inputs.</p>
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

        <div id="aggregation-result" class="result-box">The encrypted total and weighted total will appear here.</div>
      </article>

      <article class="panel">
        <div class="section-heading">
          <div>
            <p class="section-kicker">Scenario B</p>
            <h2>Binary election tally</h2>
          </div>
          <p class="section-copy">Votes stay encrypted during collection. Only the final tally is decrypted.</p>
        </div>

        <form id="election-form" class="stack-form">
          <label class="field">
            <span>Votes (0 or 1, comma separated)</span>
            <textarea id="votes-input" rows="3">1, 1, 0, 1, 0, 1, 0, 1, 1, 0</textarea>
          </label>
          <button class="button" type="submit">Tally encrypted votes</button>
        </form>

        <div id="election-result" class="result-box">The encrypted tally will appear here.</div>
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

function setupThemeToggle(): void {
  const root = document.documentElement;
  const themeToggle = byId<HTMLButtonElement>('theme-toggle');

  const currentTheme = (): 'dark' | 'light' => {
    return root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  };

  const syncToggle = (theme: 'dark' | 'light'): void => {
    themeToggle.textContent = theme === 'dark' ? '🌙' : '☀️';
    themeToggle.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
    );
  };

  syncToggle(currentTheme());

  themeToggle.addEventListener('click', () => {
    const nextTheme = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', nextTheme);
    localStorage.setItem('theme', nextTheme);
    syncToggle(nextTheme);
  });
}

const keyForm = byId<HTMLFormElement>('key-form');
const bitLengthSelect = byId<HTMLSelectElement>('bit-length');
const generateButton = byId<HTMLButtonElement>('generate-key');
const keyStatus = byId<HTMLSpanElement>('key-status');
const keyPercent = byId<HTMLSpanElement>('key-percent');
const progressFill = byId<HTMLDivElement>('progress-fill');
const metricBits = byId<HTMLElement>('metric-bits');
const metricN = byId<HTMLElement>('metric-n');
const metricG = byId<HTMLElement>('metric-g');
const metricLambda = byId<HTMLElement>('metric-lambda');
const plaintextInput = byId<HTMLInputElement>('plaintext-input');
const ciphertextOutput = byId<HTMLTextAreaElement>('ciphertext-output');
const randomizerOutput = byId<HTMLTextAreaElement>('randomizer-output');
const encryptForm = byId<HTMLFormElement>('encrypt-form');
const decryptForm = byId<HTMLFormElement>('decrypt-form');
const decryptInput = byId<HTMLTextAreaElement>('decrypt-input');
const decryptResult = byId<HTMLDivElement>('decrypt-result');
const sumForm = byId<HTMLFormElement>('sum-form');
const sumAInput = byId<HTMLInputElement>('sum-a');
const sumBInput = byId<HTMLInputElement>('sum-b');
const sumCiphertext = byId<HTMLTextAreaElement>('sum-ciphertext');
const sumResult = byId<HTMLDivElement>('sum-result');
const aggregationForm = byId<HTMLFormElement>('aggregation-form');
const countsInput = byId<HTMLTextAreaElement>('counts-input');
const weightsInput = byId<HTMLTextAreaElement>('weights-input');
const aggregationResult = byId<HTMLDivElement>('aggregation-result');
const electionForm = byId<HTMLFormElement>('election-form');
const votesInput = byId<HTMLTextAreaElement>('votes-input');
const electionResult = byId<HTMLDivElement>('election-result');

const requiresKeyControls = Array.from(
  document.querySelectorAll<HTMLButtonElement>('button:not(#generate-key)'),
);

const keygenWorker = new Worker(new URL('./keygen.worker.ts', import.meta.url), { type: 'module' });

let activeKeyPair: PaillierKeyPair | null = null;
let isGenerating = false;

function updateControlState(): void {
  generateButton.disabled = isGenerating;

  for (const control of requiresKeyControls) {
    control.disabled = !activeKeyPair || isGenerating;
  }
}

function setProgress(stage: string, percent: number): void {
  keyStatus.textContent = stage;
  keyPercent.textContent = `${Math.max(0, Math.min(100, Math.round(percent)))}%`;
  progressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
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
    setResultBox(sumResult, 'Encrypt two messages and compare the decrypted total with the plaintext sum.', 'success');
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
  sumCiphertext.value = '';
  setProgress('Dispatching key generation worker...', 2);

  const request: GenerateRequest = {
    type: 'generate',
    bitLength: Number(bitLengthSelect.value),
  };

  keygenWorker.postMessage(request);
});

encryptForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const message = parseNonNegativeBigInt(plaintextInput.value, 'Plaintext');
    const encrypted = encrypt(message, keyPair.publicKey);

    ciphertextOutput.value = encrypted.ciphertext.toString();
    randomizerOutput.value = encrypted.r.toString();
    decryptInput.value = encrypted.ciphertext.toString();
    setResultBox(
      decryptResult,
      `Ciphertext generated for plaintext <strong>${message.toString()}</strong>. Decrypt it below or re-encrypt the same message to observe fresh randomness.`,
      'success',
    );
  } catch (error) {
    setResultBox(decryptResult, error instanceof Error ? error.message : 'Encryption failed.', 'error');
  }
});

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

sumForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const left = parseNonNegativeBigInt(sumAInput.value, 'Message A');
    const right = parseNonNegativeBigInt(sumBInput.value, 'Message B');
    const encryptedLeft = encrypt(left, keyPair.publicKey);
    const encryptedRight = encrypt(right, keyPair.publicKey);
    const encryptedTotal = addCiphertexts(encryptedLeft.ciphertext, encryptedRight.ciphertext, keyPair.publicKey);
    const decryptedTotal = decrypt(encryptedTotal, keyPair);

    sumCiphertext.value = encryptedTotal.toString();
    setResultBox(
      sumResult,
      [
        `A ciphertext preview: <strong>${preview(encryptedLeft.ciphertext)}</strong>`,
        `B ciphertext preview: <strong>${preview(encryptedRight.ciphertext)}</strong>`,
        `Plaintext sum modulo N: <strong>${decryptedTotal.toString()}</strong>`,
      ].join('<br />'),
      'success',
    );
  } catch (error) {
    setResultBox(sumResult, error instanceof Error ? error.message : 'Encrypted sum failed.', 'error');
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
    const previews = scenario.hospitals
      .map((hospital) => `${hospital.id}: ${preview(hospital.encryptedCount)}`)
      .join('<br />');

    setResultBox(
      aggregationResult,
      [
        `Encrypted rows:<br />${previews}`,
        `Decrypted aggregate total: <strong>${decryptedTotal.toString()}</strong>`,
        `Weighted total: <strong>${decryptedWeighted.toString()}</strong>`,
      ].join('<br /><br />'),
      'success',
    );
  } catch (error) {
    setResultBox(aggregationResult, error instanceof Error ? error.message : 'Aggregation failed.', 'error');
  }
});

electionForm.addEventListener('submit', (event) => {
  event.preventDefault();

  try {
    const keyPair = requireKeyPair();
    const votes = parseVoteList(votesInput.value);
    const scenario = simulatePrivateElection(votes, keyPair.publicKey);
    const decryptedTally = decrypt(scenario.encryptedTally, keyPair);
    const previews = scenario.encryptedVotes
      .map((vote) => `${vote.voterId}: ${preview(vote.encryptedVote)}`)
      .join('<br />');

    setResultBox(
      electionResult,
      [
        `Encrypted votes:<br />${previews}`,
        `Decrypted tally: <strong>${decryptedTally.toString()} / ${votes.length}</strong>`,
      ].join('<br /><br />'),
      'success',
    );
  } catch (error) {
    setResultBox(electionResult, error instanceof Error ? error.message : 'Election tally failed.', 'error');
  }
});

updateControlState();
setupThemeToggle();