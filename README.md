# crypto-lab-paillier-gate

## What It Is

crypto-lab-paillier-gate is a browser demo of the Paillier additive homomorphic cryptosystem implemented in TypeScript with BigInt arithmetic. Paillier is an asymmetric public-key encryption scheme with additive homomorphism, so it can combine encrypted values and reveal only the final sum after decryption. That makes it useful for privacy-preserving totals such as vote counts and institution-level aggregates. This project demonstrates the mechanics of Paillier key generation, encryption, decryption, rerandomization, and encrypted addition, but it is not an audited production cryptography library.

## When to Use It

- Use it for privacy-preserving summation workflows where multiple parties need a combined total without exposing each individual input, because Paillier supports addition directly on ciphertexts.
- Use it for binary vote tally demonstrations, because 0/1 ballots can stay encrypted during collection and only the final tally needs to be decrypted.
- Use it for weighted scoring or aggregation experiments, because the demo supports scalar multiplication and weighted sums over encrypted values.
- Do not use this demo as a production browser encryption stack, because the UI intentionally uses educational key sizes and the implementation is not hardened or audited for deployment.

## Live Demo

Live demo: [https://systemslibrarian.github.io/crypto-lab-paillier-gate/](https://systemslibrarian.github.io/crypto-lab-paillier-gate/)

The demo lets you generate a Paillier keypair, encrypt and decrypt messages, compute an encrypted sum, and run private aggregation and encrypted election tally scenarios in the browser. It explicitly supports both encrypt and decrypt flows, along with a key-size selector for generation and text controls for plaintexts, counts, weights, and votes.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-paillier-gate
cd crypto-lab-paillier-gate
npm install
npm run dev
```

No environment variables are required.

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

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*