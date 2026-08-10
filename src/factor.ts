import { gcd, lcm, modInverse } from './numbers';
import type { PaillierKeyPair, PaillierPublicKey } from './paillier';

/**
 * Factoring the public modulus is the break for Paillier: N = p·q is the only
 * thing standing between a public key and the private trapdoor
 * λ = lcm(p−1, q−1). This module runs a real Pollard rho (Brent's variant) so
 * the demo can *measure* how hard that is at each key size instead of captioning
 * the bit-length selector with "bigger is harder to factor".
 *
 * Nothing here is simulated: the same routine that recovers a 32-bit prime in a
 * few million steps is the one that runs out of budget on larger moduli, and the
 * page reports the step count and wall-clock time it actually used.
 */

export interface FactorResult {
  /** A non-trivial factor of N, or null when the budget ran out first. */
  factor: bigint | null;
  /** Modular squarings actually performed. */
  iterations: number;
  /** Wall-clock milliseconds spent. */
  ms: number;
  /** True when the search stopped because it hit the iteration budget. */
  gaveUp: boolean;
}

/** Default work budget, ~1-2 s of BigInt arithmetic in a browser worker. */
export const DEFAULT_BUDGET = 12_000_000;

function absDiff(a: bigint, b: bigint): bigint {
  return a > b ? a - b : b - a;
}

/**
 * Pollard's rho with Brent's cycle detection and batched gcds.
 *
 * Expected work to find the smaller prime factor p is O(sqrt(p)) modular
 * squarings — which is exactly the wall this exhibit is trying to show, so the
 * iteration counter is part of the result rather than an implementation detail.
 */
export function factorSemiprime(
  N: bigint,
  budget: number = DEFAULT_BUDGET,
  onProgress?: (iterations: number) => void,
): FactorResult {
  const start = Date.now();
  let iterations = 0;
  let nextReport = 500_000;

  if (N <= 1n) {
    return { factor: null, iterations, ms: Date.now() - start, gaveUp: false };
  }

  if ((N & 1n) === 0n) {
    return { factor: 2n, iterations, ms: Date.now() - start, gaveUp: false };
  }

  const batch = 128n;

  const tick = (): boolean => {
    iterations += 1;
    if (iterations >= nextReport) {
      nextReport += 500_000;
      onProgress?.(iterations);
    }
    return iterations < budget;
  };

  // Retry with a different polynomial x^2 + c if one sequence degenerates.
  for (let c = 1n; c < 32n; c += 1n) {
    let y = 2n;
    let r = 1n;
    let q = 1n;
    let g = 1n;
    let x = 0n;
    let ys = 0n;

    while (g === 1n) {
      x = y;

      for (let i = 0n; i < r; i += 1n) {
        y = (y * y + c) % N;
        if (!tick()) {
          return { factor: null, iterations, ms: Date.now() - start, gaveUp: true };
        }
      }

      let k = 0n;

      while (k < r && g === 1n) {
        ys = y;
        const limit = batch < r - k ? batch : r - k;

        for (let i = 0n; i < limit; i += 1n) {
          y = (y * y + c) % N;
          q = (q * absDiff(x, y)) % N;
          if (!tick()) {
            return { factor: null, iterations, ms: Date.now() - start, gaveUp: true };
          }
        }

        g = gcd(q, N);
        k += batch;
      }

      r *= 2n;
    }

    if (g === N) {
      // The batched gcd collapsed; walk the last block one step at a time.
      g = 1n;
      y = ys;

      while (g === 1n) {
        y = (y * y + c) % N;
        g = gcd(absDiff(x, y), N);
        if (!tick()) {
          return { factor: null, iterations, ms: Date.now() - start, gaveUp: true };
        }
      }
    }

    if (g !== N && g !== 1n) {
      return { factor: g, iterations, ms: Date.now() - start, gaveUp: false };
    }
  }

  return { factor: null, iterations, ms: Date.now() - start, gaveUp: false };
}

export interface RecoveredKey {
  p: bigint;
  q: bigint;
  lambda: bigint;
  mu: bigint;
}

/**
 * Rebuild the private key from a factor of N. This is the whole point of
 * factoring: p and q are all the private key ever was.
 */
export function recoverPrivateKey(publicKey: PaillierPublicKey, factor: bigint): RecoveredKey {
  if (factor <= 1n || publicKey.N % factor !== 0n) {
    throw new Error('Recovered factor does not divide N.');
  }

  const p = factor;
  const q = publicKey.N / factor;
  const lambda = lcm(p - 1n, q - 1n);

  if (gcd(lambda, publicKey.N) !== 1n) {
    throw new Error('Recovered lambda is not invertible mod N.');
  }

  return { p, q, lambda, mu: modInverse(lambda, publicKey.N) };
}

/** Wrap a recovered trapdoor as a keypair the normal decrypt() path accepts. */
export function keyPairFromRecovered(
  publicKey: PaillierPublicKey,
  recovered: RecoveredKey,
): PaillierKeyPair {
  return {
    publicKey,
    privateKey: {
      lambda: recovered.lambda,
      mu: recovered.mu,
      p: recovered.p,
      q: recovered.q,
    },
  };
}

/**
 * Expected modular squarings to find a prime factor of the given bit length:
 * about 1.18·sqrt(p) with p ≈ 2^primeBits. Used only to put the measured number
 * in context — the page always reports what the run actually did alongside it.
 *
 * This takes the PRIME's bit length, not the modulus'. It used to take the
 * modulus and assume p was exactly half of it, which is wrong whenever N comes
 * out a bit short of 2·primeBits — 87 of 200 keygens across the five shipped
 * sizes. The page printed both halves of the estimate, and they then disagreed
 * with each other: a 95-bit N gave "≈ 16.6M steps for a 47-bit prime", while
 * 1.18·sqrt(2^47) is 14.0M and the real primes were 48 bits (19.8M).
 */
export function expectedIterations(primeBits: number): number {
  return 1.18 * Math.pow(2, primeBits / 2);
}
