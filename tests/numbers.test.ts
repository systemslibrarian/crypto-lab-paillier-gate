import { describe, expect, it } from 'vitest';
import {
  extendedGcd,
  gcd,
  generatePrime,
  isProbablePrime,
  lcm,
  modInverse,
  modPow,
  randomBigInt,
  randomCoprime,
} from '../src/numbers';

describe('modPow', () => {
  it('computes modular exponentiation', () => {
    expect(modPow(3n, 100n, 7n)).toBe(4n);
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
  });

  it('returns 0 mod 1 and handles zero exponent', () => {
    expect(modPow(5n, 0n, 7n)).toBe(1n);
    expect(modPow(123n, 456n, 1n)).toBe(0n);
  });

  it('normalizes a negative base into the modulus range', () => {
    expect(modPow(-2n, 3n, 7n)).toBe(modPow(5n, 3n, 7n));
  });

  it('rejects a non-positive modulus', () => {
    expect(() => modPow(2n, 3n, 0n)).toThrow(/Modulus must be positive/);
    expect(() => modPow(2n, 3n, -5n)).toThrow(/Modulus must be positive/);
  });

  it('rejects a negative exponent', () => {
    expect(() => modPow(2n, -1n, 7n)).toThrow(/Exponent must be non-negative/);
  });
});

describe('extendedGcd', () => {
  it('returns a non-negative gcd and a valid Bézout identity', () => {
    for (const [a, b] of [
      [240n, 46n],
      [-48n, 18n],
      [17n, 3120n],
      [0n, 9n],
    ] as const) {
      const { gcd: g, x, y } = extendedGcd(a, b);
      expect(g).toBeGreaterThanOrEqual(0n);
      expect(a * x + b * y).toBe(g);
    }
  });
});

describe('modInverse', () => {
  it('computes the modular inverse', () => {
    expect(modInverse(17n, 3120n)).toBe(2753n);
    expect((modInverse(3n, 11n) * 3n) % 11n).toBe(1n);
  });

  it('throws when the inverse does not exist', () => {
    expect(() => modInverse(6n, 9n)).toThrow(/Modular inverse does not exist/);
  });

  it('rejects a non-positive modulus', () => {
    expect(() => modInverse(3n, 0n)).toThrow(/Modulus must be positive/);
  });
});

describe('gcd and lcm', () => {
  it('computes gcd of integers regardless of sign', () => {
    expect(gcd(48n, 18n)).toBe(6n);
    expect(gcd(-48n, 18n)).toBe(6n);
    expect(gcd(0n, 9n)).toBe(9n);
  });

  it('computes lcm and treats zero specially', () => {
    expect(lcm(4n, 6n)).toBe(12n);
    expect(lcm(0n, 5n)).toBe(0n);
    expect(lcm(5n, 0n)).toBe(0n);
  });
});

describe('randomBigInt and randomCoprime', () => {
  it('produces values in [1, max)', () => {
    for (let i = 0; i < 200; i += 1) {
      const value = randomBigInt(50n);
      expect(value).toBeGreaterThanOrEqual(1n);
      expect(value).toBeLessThan(50n);
    }
  });

  it('rejects max <= 1', () => {
    expect(() => randomBigInt(1n)).toThrow(/max must be greater than 1/);
  });

  it('returns values coprime to N', () => {
    const N = 3n * 11n;
    for (let i = 0; i < 100; i += 1) {
      expect(gcd(randomCoprime(N), N)).toBe(1n);
    }
  });

  it('rejects N <= 2 for randomCoprime', () => {
    expect(() => randomCoprime(2n)).toThrow(/N must be greater than 2/);
  });
});

describe('isProbablePrime', () => {
  it('identifies small primes and composites', () => {
    expect(isProbablePrime(2n)).toBe(true);
    expect(isProbablePrime(3n)).toBe(true);
    expect(isProbablePrime(997n)).toBe(true);
    expect(isProbablePrime(1000n)).toBe(false);
    expect(isProbablePrime(1n)).toBe(false);
    expect(isProbablePrime(0n)).toBe(false);
    expect(isProbablePrime(-7n)).toBe(false);
  });

  it('detects a known Carmichael number as composite', () => {
    expect(isProbablePrime(561n)).toBe(false);
  });

  it('rejects a non-positive round count', () => {
    expect(() => isProbablePrime(5n, 0)).toThrow(/k must be positive/);
  });
});

describe('generatePrime', () => {
  it('generates a prime of the requested bit length', () => {
    const prime = generatePrime(48);
    expect(prime.toString(2).length).toBe(48);
    expect(isProbablePrime(prime, 40)).toBe(true);
  });

  it('reports attempts through the progress callback', () => {
    let lastAttempt = 0;
    generatePrime(32, (attempts) => {
      lastAttempt = attempts;
    });
    expect(lastAttempt).toBeGreaterThanOrEqual(1);
  });

  it('rejects an invalid bit length', () => {
    expect(() => generatePrime(1)).toThrow(/bits must be an integer/);
  });

  it('two k-bit primes multiply to 2k-1 bits about two times in five, not one in four', () => {
    // Pins the Step 1 "Modulus bits" gloss. randomBigIntWithBits forces only
    // the top bit, so p and q are drawn from [2^(k-1), 2^k) and N = p·q has
    // 2k-1 bits exactly when p·q < 2^(2k-1). Writing p = 2^(k-1)·u and
    // q = 2^(k-1)·v with u, v ~ U[1,2), that is P(uv < 2) = 2·ln 2 - 1 ≈ 0.3863
    // — not the "about a quarter" this gloss used to claim. Measured 38.56%
    // over 50,000 keypairs at k = 48 (the page's 96-bit selection); the band
    // below is wide enough to never flake and still excludes 0.25.
    const EXPECTED = 2 * Math.log(2) - 1;
    expect(EXPECTED).toBeCloseTo(0.3863, 4);

    const k = 16;
    const trials = 3000;
    let short = 0;
    for (let i = 0; i < trials; i += 1) {
      const p = generatePrime(k);
      let q = generatePrime(k);
      while (q === p) q = generatePrime(k);
      if ((p * q).toString(2).length === 2 * k - 1) short += 1;
    }
    const rate = short / trials;
    expect(rate).toBeGreaterThan(0.3);
    expect(rate).toBeLessThan(0.48);
    expect(Math.abs(rate - 0.25)).toBeGreaterThan(Math.abs(rate - EXPECTED));
  }, 300_000);
});
