(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))s(n);new MutationObserver(n=>{for(const o of n)if(o.type==="childList")for(const a of o.addedNodes)a.tagName==="LINK"&&a.rel==="modulepreload"&&s(a)}).observe(document,{childList:!0,subtree:!0});function r(n){const o={};return n.integrity&&(o.integrity=n.integrity),n.referrerPolicy&&(o.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?o.credentials="include":n.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function s(n){if(n.ep)return;n.ep=!0;const o=r(n);fetch(n.href,o)}})();function q(t,e){const r=t%e;return r>=0n?r:r+e}function N(t){return t>=0n?t:-t}function O(t){if(t<0n)throw new Error("bitLength requires a non-negative value.");return t===0n?0:t.toString(2).length}function F(t){if(t<=0n)throw new Error("maxExclusive must be positive.");const e=O(t-1n),r=Math.max(1,Math.ceil(e/8)),s=r*8-e,n=new Uint8Array(r);for(;;){crypto.getRandomValues(n),s>0&&(n[0]&=255>>>s);let o=0n;for(const a of n)o=o<<8n|BigInt(a);if(o<t)return o}}function x(t,e,r){if(r<=0n)throw new Error("Modulus must be positive.");if(e<0n)throw new Error("Exponent must be non-negative.");let s=1n,n=q(t,r),o=e;for(;o>0n;)(o&1n)===1n&&(s=s*n%r),n=n*n%r,o>>=1n;return s}function K(t,e){let r=N(t),s=N(e);for(;s!==0n;)[r,s]=[s,r%s];return r}function W(t){if(t<=1n)throw new Error("max must be greater than 1.");return F(t-1n)+1n}function j(t){if(t<=2n)throw new Error("N must be greater than 2.");for(;;){const e=W(t);if(K(e,t)===1n)return e}}function p(t,e){const r=t%e;return r>=0n?r:r+e}function H(t,e){if(t<0n)throw new Error("Plaintext must be non-negative.");if(t>=e)throw new Error("Plaintext must be less than N.")}function m(t,e){H(t,e.N);const r=j(e.N),s=x(e.g,t,e.N2),n=x(r,e.N,e.N2);return{ciphertext:s*n%e.N2,r}}function U(t,e){const r=t-1n;if(r%e!==0n)throw new Error("L(x) requires (x - 1) to be divisible by N.");return r/e}function g(t,e){const{publicKey:{N:r,N2:s},privateKey:{lambda:n,mu:o}}=e,a=p(t,s),d=x(a,n,s),$=U(d,r);return p($*o,r)}function E(t,e,r){return p(t,r.N2)*p(e,r.N2)%r.N2}function X(t,e,r){const s=p(e,r.N);return x(p(t,r.N2),s,r.N2)}function J(t,e){const r=t.map((n,o)=>{const{ciphertext:a}=m(n,e);return{id:`Hospital ${String.fromCharCode(65+o)}`,privateCount:n,encryptedCount:a}}),s=r.reduce((n,o)=>E(n,o.encryptedCount,e),1n);return{hospitals:r,encryptedTotal:s}}function Q(t,e){const r=t.map((n,o)=>{if(n!==0&&n!==1)throw new Error("Votes must be 0 or 1.");const{ciphertext:a}=m(BigInt(n),e);return{voterId:`Voter ${o+1}`,encryptedVote:a}}),s=r.reduce((n,o)=>E(n,o.encryptedVote,e),1n);return{encryptedVotes:r,encryptedTally:s}}function Y(t,e,r){if(t.length!==e.length)throw new Error("encryptedValues and weights must have the same length.");return t.reduce((s,n,o)=>{const a=X(n,e[o],r);return E(s,a,r)},1n)}const B=document.querySelector("#app");if(!B)throw new Error("App root not found.");B.innerHTML=`
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
`;function i(t){const e=document.getElementById(t);if(!e)throw new Error(`Missing element: ${t}`);return e}function h(t,e){const r=t.trim();if(!r)throw new Error(`${e} is required.`);let s;try{s=BigInt(r)}catch{throw new Error(`${e} must be an integer.`)}if(s<0n)throw new Error(`${e} must be non-negative.`);return s}function T(t,e){const r=t.split(",").map(s=>s.trim()).filter(Boolean);if(r.length===0)throw new Error(`${e} must contain at least one value.`);return r.map((s,n)=>h(s,`${e} #${n+1}`))}function Z(t){const e=t.split(",").map(r=>r.trim()).filter(Boolean);if(e.length===0)throw new Error("Votes must contain at least one entry.");return e.map((r,s)=>{if(r!=="0"&&r!=="1")throw new Error(`Vote #${s+1} must be 0 or 1.`);return Number(r)})}function l(t,e=18){const r=t.toString();return r.length<=e*2+3?r:`${r.slice(0,e)}...${r.slice(-e)}`}function c(t,e,r="neutral"){t.dataset.tone=r,t.innerHTML=e}function _(){const t=document.documentElement,e=i("theme-toggle"),r=()=>t.getAttribute("data-theme")==="light"?"light":"dark",s=n=>{e.textContent=n==="dark"?"🌙":"☀️",e.setAttribute("aria-label",n==="dark"?"Switch to light mode":"Switch to dark mode")};s(r()),e.addEventListener("click",()=>{const n=r()==="dark"?"light":"dark";t.setAttribute("data-theme",n),localStorage.setItem("theme",n),s(n)})}const ee=i("key-form"),te=i("bit-length"),re=i("generate-key"),ne=i("key-status"),se=i("key-percent"),oe=i("progress-fill"),ie=i("metric-bits"),I=i("metric-n"),M=i("metric-g"),A=i("metric-lambda"),ae=i("plaintext-input"),V=i("ciphertext-output"),D=i("randomizer-output"),ce=i("encrypt-form"),le=i("decrypt-form"),P=i("decrypt-input"),u=i("decrypt-result"),pe=i("sum-form"),ue=i("sum-a"),de=i("sum-b"),G=i("sum-ciphertext"),S=i("sum-result"),me=i("aggregation-form"),ge=i("counts-input"),he=i("weights-input"),C=i("aggregation-result"),ye=i("election-form"),fe=i("votes-input"),L=i("election-result"),be=Array.from(document.querySelectorAll("button:not(#generate-key)")),R=new Worker(new URL("/crypto-lab-paillier-gate/assets/keygen.worker-DpLxozXy.js",import.meta.url),{type:"module"});let y=null,f=!1;function k(){re.disabled=f;for(const t of be)t.disabled=!y||f}function w(t,e){ne.textContent=t,se.textContent=`${Math.max(0,Math.min(100,Math.round(e)))}%`,oe.style.width=`${Math.max(0,Math.min(100,e))}%`}function z(t){ie.textContent=`${t.publicKey.bitLength}`,I.textContent=l(t.publicKey.N),M.textContent=l(t.publicKey.g),A.textContent=l(t.privateKey.lambda)}function b(){if(!y)throw new Error("Generate a keypair first.");return y}R.addEventListener("message",t=>{const e=t.data;if(e.type==="progress"){w(e.stage,e.percent);return}if(f=!1,k(),e.type==="success"){y=e.keyPair,z(e.keyPair),w("Keypair ready. The playground is unlocked.",100),c(u,"Paste any ciphertext from this page into the decrypt box, then decode it here.","success"),c(S,"Encrypt two messages and compare the decrypted total with the plaintext sum.","success"),c(C,"Run a hospital-style aggregation or weighted total with the new keypair.","success"),c(L,"Run an encrypted binary vote tally with the new keypair.","success"),k();return}w(e.message,0),c(u,e.message,"error")});ee.addEventListener("submit",t=>{if(t.preventDefault(),f)return;y=null,f=!0,k(),z({publicKey:{N:0n,g:0n,N2:0n,bitLength:0},privateKey:{lambda:0n,mu:0n,p:0n,q:0n}}),I.textContent="Generating...",M.textContent="Generating...",A.textContent="Generating...",V.value="",D.value="",P.value="",G.value="",w("Dispatching key generation worker...",2);const e={type:"generate",bitLength:Number(te.value)};R.postMessage(e)});ce.addEventListener("submit",t=>{t.preventDefault();try{const e=b(),r=h(ae.value,"Plaintext"),s=m(r,e.publicKey);V.value=s.ciphertext.toString(),D.value=s.r.toString(),P.value=s.ciphertext.toString(),c(u,`Ciphertext generated for plaintext <strong>${r.toString()}</strong>. Decrypt it below or re-encrypt the same message to observe fresh randomness.`,"success")}catch(e){c(u,e instanceof Error?e.message:"Encryption failed.","error")}});le.addEventListener("submit",t=>{t.preventDefault();try{const e=b(),r=h(P.value,"Ciphertext"),s=g(r,e);c(u,`Decrypted value: <strong>${s.toString()}</strong>`,"success")}catch(e){c(u,e instanceof Error?e.message:"Decryption failed.","error")}});pe.addEventListener("submit",t=>{t.preventDefault();try{const e=b(),r=h(ue.value,"Message A"),s=h(de.value,"Message B"),n=m(r,e.publicKey),o=m(s,e.publicKey),a=E(n.ciphertext,o.ciphertext,e.publicKey),d=g(a,e);G.value=a.toString(),c(S,[`A ciphertext preview: <strong>${l(n.ciphertext)}</strong>`,`B ciphertext preview: <strong>${l(o.ciphertext)}</strong>`,`Plaintext sum modulo N: <strong>${d.toString()}</strong>`].join("<br />"),"success")}catch(e){c(S,e instanceof Error?e.message:"Encrypted sum failed.","error")}});me.addEventListener("submit",t=>{t.preventDefault();try{const e=b(),r=T(ge.value,"Counts"),s=T(he.value,"Weights"),n=J(r,e.publicKey),o=g(n.encryptedTotal,e),a=Y(n.hospitals.map(v=>v.encryptedCount),s,e.publicKey),d=g(a,e),$=n.hospitals.map(v=>`${v.id}: ${l(v.encryptedCount)}`).join("<br />");c(C,[`Encrypted rows:<br />${$}`,`Decrypted aggregate total: <strong>${o.toString()}</strong>`,`Weighted total: <strong>${d.toString()}</strong>`].join("<br /><br />"),"success")}catch(e){c(C,e instanceof Error?e.message:"Aggregation failed.","error")}});ye.addEventListener("submit",t=>{t.preventDefault();try{const e=b(),r=Z(fe.value),s=Q(r,e.publicKey),n=g(s.encryptedTally,e),o=s.encryptedVotes.map(a=>`${a.voterId}: ${l(a.encryptedVote)}`).join("<br />");c(L,[`Encrypted votes:<br />${o}`,`Decrypted tally: <strong>${n.toString()} / ${r.length}</strong>`].join("<br /><br />"),"success")}catch(e){c(L,e instanceof Error?e.message:"Election tally failed.","error")}});k();_();
