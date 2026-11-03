# crypto-lab-paillier-gate

## What It Is

crypto-lab-paillier-gate is a browser demo of the Paillier probabilistic, additively homomorphic cryptosystem implemented in TypeScript with BigInt arithmetic. In a protocol that separates data owners, the ciphertext aggregator, and authorized key holders, Paillier can combine encrypted values before an authorized party decrypts the final modular total. This single-page lesson intentionally sees the learner's inputs and owns the private key so it can verify every result; it models those separated roles rather than providing that confidentiality boundary itself. It demonstrates key generation, encryption, decryption, rerandomization, encrypted addition, and their limits, but it is not an audited production cryptography library.

## When to Use It

- Use it to study privacy-preserving summation designs with separated roles, because Paillier supports addition directly on ciphertexts.
- Use it for binary vote tally demonstrations, because 0/1 ballots can stay encrypted during collection and only the final tally needs to be decrypted.
- Use it for weighted scoring or aggregation experiments, because the demo supports scalar multiplication and weighted sums over encrypted values.
- Do not use it as a production browser encryption stack, because it is a demo app and does not provide hardened operational controls.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/)**

The demo lets you generate a Paillier keypair, encrypt and decrypt messages, compute an encrypted sum, and run private aggregation and encrypted election tally scenarios in the browser. It explicitly supports both encrypt and decrypt flows, along with a key-size selector for generation and text controls for plaintexts, counts, weights, and votes.

To make the homomorphic "magic" observable rather than asserted, the demo also includes:

- A **homomorphic-addition ledger** in Step 3 that shows the full `Enc(A)`, `Enc(B)`, and product ciphertexts with a literal `× (mod N²)` operator and a `decrypt →` arrow to `A + B`, plus an inline callout proving the product is *not* the integer sum of the two ciphertexts — the page decrypts that integer sum too and prints the wrong value it yields, so ciphertext multiplication being the operation that maps to plaintext addition is demonstrated, not claimed.
- A **ciphertext hand-off**: encrypt a value in Step 2 and send that exact ciphertext into Step 3 so you combine data you personally encrypted, instead of the demo re-encrypting behind the scenes.
- A **"same message, different ciphertext"** stack (an *Encrypt again* button) that illustrates Paillier's probabilistic randomness: identical plaintexts yield visibly different ciphertexts. Each row is decrypted with the private key as it is added and captioned with that decryption. This observation does not prove semantic security; the original Paillier result establishes that property under the decisional composite residuosity assumption.
- A **re-randomize** control that folds a fresh `rᴺ` factor into an existing ciphertext using only the public key — the ciphertext changes completely, the plaintext does not, and the new row's caption is the real decryption of the refreshed ciphertext.
- An **interactive modulus-overflow preset** that forces an encrypted sum past `N` so you can watch decryption silently wrap to the wrong value, with a callout explaining the plaintext-space bound.
- A **factoring attack on the key you just generated**: a real Pollard rho (Brent's variant) runs in a worker against `N` under a fixed 12,000,000-step budget. On a 64-bit modulus it splits `N` in a few hundred thousand modular squarings, rebuilds `λ = lcm(p−1, q−1)` from the recovered primes, checks that against the private `λ` the keygen worker produced, and decrypts your Step 2 ciphertext with the key it just derived. At larger sizes the same routine exhausts its budget and says so, printing the steps and milliseconds it actually burned. "Bigger is harder to factor" becomes a measurement rather than a caption on the bit-length selector.
- A **stepped decryption**: press once per operation to walk `c → u = c^λ mod N² → L(u) = (u−1)/N → m = L(u)·μ mod N` on the live ciphertext, with the final step cross-checked against what `decrypt()` returns for the same input.
- A **malleability attack on a sealed ballot** (Scenario B). The attacker encrypts a boost under the *public* key, multiplies it into another voter's ciphertext, and the tally decrypts that much higher. A toggle turns on a domain-separated HMAC-SHA256 over the voter identifier and ciphertext; the ballot box verifies it with Web Crypto and rejects both the forged record and duplicate voter identifiers. This blocks the demonstrated outsider rewrite, but it is not a complete election protocol.
- **Plain-language glosses** on the `N`, `g`, and `λ` metric cards and a collapsible *What's happening under the hood* panel carrying the key-generation and encryption math onto the page.

The two scenarios make deliberately different arguments. Scenario A models the arithmetic used by a confidential aggregation protocol: it runs both the plain sum `∏ Enc(xᵢ)` and the weighted sum `∏ Enc(xᵢ)^wᵢ`, printing each row's `Enc(x)^w` contribution and checking the decrypted modular totals against the learner-visible inputs. The page itself is not confidential because it owns both those inputs and the private key. Scenario B is integrity: the same algebra, turned against the voter.

## What Can Go Wrong

- The implementation uses small educational key sizes and does not constant-time its modular arithmetic, so its modular exponentiation can leak secrets through timing or other side channels.
- Reusing or omitting the fresh randomness `r` in `c = gᵐ · rᴺ mod N²` makes encryption deterministic and breaks semantic security.
- Additive homomorphism is also malleability: anyone holding a ciphertext can add to it or rescale it, so Paillier alone provides no integrity and needs separate authentication.
- Plaintexts must stay below the modulus `N`; an encrypted sum that overflows `N` wraps around modulo `N` and decrypts to the wrong value.
- Weak prime generation for `p` and `q`, or too small a modulus, lets an attacker factor `N` and recover the private key.
- A MAC over this demo's voter identifier and ciphertext does not establish voter eligibility, prove that a plaintext is 0 or 1, prevent replay across election contexts, distribute decryption trust, or provide availability and public auditability.

## Real-World Usage

- Some privacy-preserving e-voting constructions use threshold Paillier with eligibility, validity-proof, replay, audit and availability mechanisms so authorized key holders open only an aggregate rather than individual ballots.
- Threshold ECDSA protocols such as GG18 use Paillier-based multiplication-to-addition subprotocols during distributed signing; the lab demonstrates the underlying additive operation, not a threshold-ECDSA implementation.
- Federated learning and private analytics use additively homomorphic encryption to aggregate model updates or statistics without exposing individual contributions.
- Privacy-preserving advertising and data-aggregation pipelines use Paillier-style additive HE to compute encrypted sums across mutually distrusting parties.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-paillier-gate
cd crypto-lab-paillier-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-elgamal-plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — ElGamal homomorphism and ciphertext re-randomization.
- [crypto-lab-fhe-arena](https://systemslibrarian.github.io/crypto-lab-fhe-arena/) — BGV/BFV fully homomorphic encryption with SIMD batching.
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/#election) — a quorum opens the election total, with a 0-or-1 proof against dishonest voters. This lab instead uses one decryption key and a MAC against an outsider rewriting an honest ballot; that MAC cannot establish the voter's plaintext is a permitted vote.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — Shamir-based secure sum, an MPC alternative to HE aggregation.

## How It Works

Paillier is built on the decisional composite residuosity assumption. The [original EUROCRYPT '99 paper](https://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf) proves Scheme 1 semantically secure if and only if that assumption holds; observing randomized samples in this demo illustrates the construction but is not that proof. Key generation picks two primes `p` and `q`, forms the modulus `N = p · q`, and uses the generator `g = N + 1`. A plaintext `m` is encrypted as `c = gᵐ · rᴺ mod N²` with fresh randomness `r`, so the same message yields a different ciphertext every time. Decryption recovers `m` with the private values `λ = lcm(p−1, q−1)` and `μ = λ⁻¹ mod N` via `m = L(c^λ mod N²) · μ mod N`, where `L(x) = (x − 1) / N`.

The scheme is **additively homomorphic**: multiplying two ciphertexts modulo `N²` decrypts to the sum of their plaintexts, and raising a ciphertext to a scalar power decrypts to the scaled plaintext. Those two facts are what make the encrypted aggregation and election-tally scenarios possible.

All arithmetic uses native `BigInt`, randomness comes from the Web Crypto API (`crypto.getRandomValues`), and key generation runs in a Web Worker so the UI stays responsive during prime search.

## Testing and Verification

```bash
npm test         # Vitest unit suite (number theory, Paillier core, factoring, ballots, scenarios)
npm run verify   # End-to-end verification gate, including a 2048-bit round-trip,
                 # the 64-bit factoring break, and the ballot forgery with and without MAC
npm run check    # Typecheck + tests + verify (the full local gate)
npm run test:a11y # Playwright: WCAG A/AA scan plus functional gates on every exhibit
```

The Playwright suite is not only an accessibility scan: `e2e/exhibits.spec.ts` drives the real page and
asserts the computed outcome of each exhibit, including the paths where an attack is supposed to fail —
the 192-bit factoring run that must give up, and the forged ballot that Encrypt-then-MAC must reject.

Every push and pull request runs the typecheck, build, unit tests, and verification gate in GitHub Actions; the GitHub Pages deploy only runs after that gate passes.

## Accessibility and Mobile

The UI targets WCAG 2.1 AA and works down to small phone widths: a skip-to-content link, keyboard-visible focus rings, `aria-live` result regions and a labelled progress bar, AA-contrast text and controls in both light and dark themes, 44px touch targets, a 16px input-font floor to prevent iOS focus-zoom, `prefers-reduced-motion` support, and a fluid grid that reflows from four columns down to one.

## Tech Stack

TypeScript, Vite, and a Web Worker for key generation — no cryptography dependencies; the Paillier implementation is self-contained. Tested with Vitest and deployed as a static site to GitHub Pages.

## Security Notes

This is an educational demo, **not** an audited production cryptography library. It intentionally offers small key sizes for fast in-browser generation, does not constant-time its modular arithmetic, and is not hardened against side-channel attacks. Do not use it to protect real data.

## License

Released under the [MIT License](LICENSE).

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
