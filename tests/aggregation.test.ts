import { beforeAll, describe, expect, it } from 'vitest';
import {
  simulatePrivateAggregation,
  simulatePrivateElection,
  weightedSum,
} from '../src/aggregation';
import { decrypt, encrypt, generateKeyPair, type PaillierKeyPair } from '../src/paillier';

let keyPair: PaillierKeyPair;

beforeAll(async () => {
  keyPair = await generateKeyPair(128);
});

describe('simulatePrivateAggregation', () => {
  it('produces an encrypted total that decrypts to the sum', () => {
    const counts = [10n, 25n, 17n, 8n, 30n];
    const scenario = simulatePrivateAggregation(counts, keyPair.publicKey);
    expect(scenario.hospitals).toHaveLength(counts.length);
    expect(scenario.hospitals[0].id).toBe('Hospital A');
    expect(decrypt(scenario.encryptedTotal, keyPair)).toBe(90n);
  });
});

describe('simulatePrivateElection', () => {
  it('tallies encrypted binary votes', () => {
    const scenario = simulatePrivateElection([1, 1, 0, 1, 0, 1, 0, 1, 1, 0], keyPair.publicKey);
    expect(scenario.encryptedVotes).toHaveLength(10);
    expect(decrypt(scenario.encryptedTally, keyPair)).toBe(6n);
  });

  it('rejects non-binary votes', () => {
    expect(() => simulatePrivateElection([0, 2], keyPair.publicKey)).toThrow(/0 or 1/);
  });
});

describe('weightedSum', () => {
  it('computes a weighted total over ciphertexts', () => {
    const encrypted = [10n, 20n, 30n].map((v) => encrypt(v, keyPair.publicKey).ciphertext);
    const result = weightedSum(encrypted, [1n, 2n, 3n], keyPair.publicKey);
    expect(decrypt(result, keyPair)).toBe(140n);
  });

  it('rejects mismatched lengths', () => {
    const encrypted = [encrypt(1n, keyPair.publicKey).ciphertext];
    expect(() => weightedSum(encrypted, [1n, 2n], keyPair.publicKey)).toThrow(/same length/);
  });
});
