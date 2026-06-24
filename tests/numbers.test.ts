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
});
