import { beforeAll, describe, expect, it } from 'vitest';
import {
  addCiphertexts,
  addPlaintext,
  decrypt,
  encrypt,
  generateKeyPair,
  L,
  multiplyByScalar,
  rerandomize,
  type PaillierKeyPair,
} from '../src/paillier';

let keyPair: PaillierKeyPair;

beforeAll(async () => {
  // A small key keeps the suite fast while exercising the full algorithm.
  keyPair = await generateKeyPair(128);
});

describe('generateKeyPair', () => {
  it('rejects a bit length below the minimum', async () => {
    await expect(generateKeyPair(11)).rejects.toThrow(/bitLength must be an integer/);
  });

  it('produces consistent public key material', () => {
    const { N, g, N2, bitLength } = keyPair.publicKey;
    expect(g).toBe(N + 1n);
    expect(N2).toBe(N * N);
    expect(N.toString(2).length).toBe(bitLength);
  });

  it('reports progress', async () => {
    const stages: number[] = [];
    await generateKeyPair(64, (_stage, percent) => stages.push(percent));
    expect(stages.length).toBeGreaterThan(0);
    expect(Math.max(...stages)).toBe(100);
  });
});

describe('encrypt / decrypt', () => {
  it('round-trips a plaintext', () => {
    const { ciphertext } = encrypt(42n, keyPair.publicKey);
    expect(decrypt(ciphertext, keyPair)).toBe(42n);
  });

  it('round-trips zero', () => {
    const { ciphertext } = encrypt(0n, keyPair.publicKey);
    expect(decrypt(ciphertext, keyPair)).toBe(0n);
  });

  it('uses fresh randomness for every encryption', () => {
    const a = encrypt(42n, keyPair.publicKey);
    const b = encrypt(42n, keyPair.publicKey);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(decrypt(a.ciphertext, keyPair)).toBe(42n);
    expect(decrypt(b.ciphertext, keyPair)).toBe(42n);
  });

  it('rejects out-of-range plaintexts', () => {
    expect(() => encrypt(-1n, keyPair.publicKey)).toThrow(/non-negative/);
    expect(() => encrypt(keyPair.publicKey.N, keyPair.publicKey)).toThrow(/less than N/);
  });
});

describe('L function', () => {
  it('computes (x - 1) / N when divisible', () => {
    expect(L(1n + 5n * 7n, 7n)).toBe(5n);
  });

  it('throws when (x - 1) is not divisible by N', () => {
    expect(() => L(10n, 7n)).toThrow(/divisible by N/);
  });
});

describe('homomorphic operations', () => {
  it('adds two ciphertexts', () => {
    const a = encrypt(7n, keyPair.publicKey);
    const b = encrypt(13n, keyPair.publicKey);
    const sum = addCiphertexts(a.ciphertext, b.ciphertext, keyPair.publicKey);
    expect(decrypt(sum, keyPair)).toBe(20n);
  });

  it('adds a plaintext to a ciphertext', () => {
    const c = encrypt(10n, keyPair.publicKey);
    expect(decrypt(addPlaintext(c.ciphertext, 5n, keyPair.publicKey), keyPair)).toBe(15n);
  });

  it('multiplies a ciphertext by a scalar', () => {
    const c = encrypt(6n, keyPair.publicKey);
    expect(decrypt(multiplyByScalar(c.ciphertext, 7n, keyPair.publicKey), keyPair)).toBe(42n);
  });

  it('rerandomizes without changing the plaintext', () => {
    const c = encrypt(99n, keyPair.publicKey);
    const fresh = rerandomize(c.ciphertext, keyPair.publicKey);
    expect(fresh).not.toBe(c.ciphertext);
    expect(decrypt(fresh, keyPair)).toBe(99n);
  });

  it('wraps a sum that exceeds N modulo N', () => {
    const { N } = keyPair.publicKey;
    const a = encrypt(N - 2n, keyPair.publicKey);
    const b = encrypt(5n, keyPair.publicKey);
    const sum = addCiphertexts(a.ciphertext, b.ciphertext, keyPair.publicKey);
    expect(decrypt(sum, keyPair)).toBe(3n); // (N - 2 + 5) mod N
  });
});
