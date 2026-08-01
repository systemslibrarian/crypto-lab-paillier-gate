# crypto-lab-paillier-gate

## What It Is

crypto-lab-paillier-gate is a browser demo of the Paillier additive homomorphic cryptosystem implemented in TypeScript with BigInt arithmetic. Paillier is an asymmetric public-key encryption scheme with additive homomorphism, so it can combine encrypted values and reveal only the final sum after decryption. That makes it useful for privacy-preserving totals such as vote counts and institution-level aggregates. This project demonstrates the mechanics of Paillier key generation, encryption, decryption, rerandomization, and encrypted addition, but it is not an audited production cryptography library.

## When to Use It

- Use it for privacy-preserving summation workflows where multiple parties need a combined total without exposing each individual input, because Paillier supports addition directly on ciphertexts.
- Use it for binary vote tally demonstrations, because 0/1 ballots can stay encrypted during collection and only the final tally needs to be decrypted.
- Use it for weighted scoring or aggregation experiments, because the demo supports scalar multiplication and weighted sums over encrypted values.
- Do NOT use this demo as a production browser encryption stack — it is a teaching demo that intentionally uses educational key sizes and is not hardened or audited for deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/)**

The demo lets you generate a Paillier keypair, encrypt and decrypt messages, compute an encrypted sum, and run private aggregation and encrypted election tally scenarios in the browser. It explicitly supports both encrypt and decrypt flows, along with a key-size selector for generation and text controls for plaintexts, counts, weights, and votes.

To make the homomorphic "magic" observable rather than asserted, the demo also includes:

- A **homomorphic-addition ledger** in Step 3 that shows the full `Enc(A)`, `Enc(B)`, and product ciphertexts with a literal `× (mod N²)` operator and a `decrypt →` arrow to `A + B`, plus an inline callout proving the product is *not* the integer sum of the two ciphertexts (that value decrypts to garbage) — ciphertext multiplication is what maps to plaintext addition.
- A **ciphertext hand-off**: encrypt a value in Step 2 and send that exact ciphertext into Step 3 so you combine data you personally encrypted, instead of the demo re-encrypting behind the scenes.
- A **"same message, different ciphertext"** stack (an *Encrypt again* button) that visualizes semantic security: identical plaintexts yield visibly different ciphertexts that all decrypt to the same value.
- An **interactive modulus-overflow preset** that forces an encrypted sum past `N` so you can watch decryption silently wrap to the wrong value, with a callout explaining the plaintext-space bound.
- **Plain-language glosses** on the `N`, `g`, and `λ` metric cards and a collapsible *What's happening under the hood* panel carrying the key-generation and encryption math onto the page.

## What Can Go Wrong

- The implementation uses small educational key sizes and does not constant-time its modular arithmetic, so its modular exponentiation can leak secrets through timing or other side channels.
- Reusing or omitting the fresh randomness `r` in `c = gᵐ · rᴺ mod N²` makes encryption deterministic and breaks semantic security.
- Additive homomorphism is also malleability: anyone holding a ciphertext can add to it or rescale it, so Paillier alone provides no integrity and needs separate authentication.
- Plaintexts must stay below the modulus `N`; an encrypted sum that overflows `N` wraps around modulo `N` and decrypts to the wrong value.
- Weak prime generation for `p` and `q`, or too small a modulus, lets an attacker factor `N` and recover the private key.

## Real-World Usage

- Privacy-preserving e-voting systems use Paillier to tally encrypted ballots so individual votes are never decrypted, only the final count.
- Threshold ECDSA wallet protocols such as GG18/GG20 use Paillier encryption during distributed key generation and signing.
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
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) — t-of-n threshold ElGamal decryption with NIZK proofs.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — Shamir-based secure sum, an MPC alternative to HE aggregation.

## How It Works

Paillier is built on the decisional composite residuosity assumption. Key generation picks two primes `p` and `q`, forms the modulus `N = p · q`, and uses the generator `g = N + 1`. A plaintext `m` is encrypted as `c = gᵐ · rᴺ mod N²` with fresh randomness `r`, so the same message yields a different ciphertext every time. Decryption recovers `m` with the private values `λ = lcm(p−1, q−1)` and `μ = λ⁻¹ mod N` via `m = L(c^λ mod N²) · μ mod N`, where `L(x) = (x − 1) / N`.

The scheme is **additively homomorphic**: multiplying two ciphertexts modulo `N²` decrypts to the sum of their plaintexts, and raising a ciphertext to a scalar power decrypts to the scaled plaintext. Those two facts are what make the encrypted aggregation and election-tally scenarios possible.

All arithmetic uses native `BigInt`, randomness comes from the Web Crypto API (`crypto.getRandomValues`), and key generation runs in a Web Worker so the UI stays responsive during prime search.

## Testing and Verification

```bash
npm test       # Vitest unit suite (number theory, Paillier core, scenarios)
npm run verify # End-to-end verification gate, including a 2048-bit round-trip
npm run check  # Typecheck + tests + verify (the full local gate)
```

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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
