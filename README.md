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

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*