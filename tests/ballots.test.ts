import { beforeAll, describe, expect, it } from 'vitest';
import {
  forgeBallot,
  generateBallotKey,
  runBallotBox,
  sealBallots,
  tallyBallots,
  verifyBallot,
} from '../src/ballots';
import { decrypt, generateKeyPair, type PaillierKeyPair } from '../src/paillier';

let keyPair: PaillierKeyPair;
let ballotKey: CryptoKey;

const VOTES = [1, 1, 0, 1, 0, 1, 0, 1, 1, 0];
const HONEST_TALLY = 6n;

beforeAll(async () => {
  keyPair = await generateKeyPair(128);
  ballotKey = await generateBallotKey();
});

describe('sealBallots', () => {
  it('tallies to the plaintext sum of the votes', async () => {
    const ballots = await sealBallots(VOTES, keyPair.publicKey, ballotKey);
    expect(ballots).toHaveLength(VOTES.length);
    expect(decrypt(tallyBallots(ballots, keyPair.publicKey), keyPair)).toBe(HONEST_TALLY);
  });

  it('rejects non-binary votes', async () => {
    await expect(sealBallots([0, 2], keyPair.publicKey, ballotKey)).rejects.toThrow(/0 or 1/);
  });

  it('tags every ballot so it verifies as sealed', async () => {
    const ballots = await sealBallots([1, 0], keyPair.publicKey, ballotKey);
    for (const ballot of ballots) {
      expect(await verifyBallot(ballot, ballotKey)).toBe(true);
    }
  });
});

describe('forgeBallot (malleability)', () => {
  it('inflates the tally by the injected amount using only the public key', async () => {
    const ballots = await sealBallots(VOTES, keyPair.publicKey, ballotKey);
    const forged = forgeBallot(ballots[0].ciphertext, 100n, keyPair.publicKey);

    ballots[0] = { ...ballots[0], ciphertext: forged.forgedCiphertext, tampered: true };

    const rigged = decrypt(tallyBallots(ballots, keyPair.publicKey), keyPair);
    expect(rigged).toBe(HONEST_TALLY + 100n);
  });

  it('leaves the victim ciphertext unrecognisable but still a valid ballot', async () => {
    const ballots = await sealBallots([1], keyPair.publicKey, ballotKey);
    const forged = forgeBallot(ballots[0].ciphertext, 41n, keyPair.publicKey);

    expect(forged.forgedCiphertext).not.toBe(ballots[0].ciphertext);
    expect(decrypt(forged.forgedCiphertext, keyPair)).toBe(42n);
  });

  it('rejects a negative boost', async () => {
    const ballots = await sealBallots([1], keyPair.publicKey, ballotKey);
    expect(() => forgeBallot(ballots[0].ciphertext, -1n, keyPair.publicKey)).toThrow(/non-negative/);
  });
});

describe('runBallotBox', () => {
  it('accepts the forgery when it does not authenticate ballots', async () => {
    const ballots = await sealBallots(VOTES, keyPair.publicKey, ballotKey);
    const forged = forgeBallot(ballots[2].ciphertext, 100n, keyPair.publicKey);
    ballots[2] = { ...ballots[2], ciphertext: forged.forgedCiphertext, tampered: true };

    const box = await runBallotBox(ballots, keyPair.publicKey, ballotKey, false);

    expect(box.rejected).toHaveLength(0);
    expect(box.accepted).toHaveLength(VOTES.length);
    expect(decrypt(box.encryptedTally, keyPair)).toBe(HONEST_TALLY + 100n);
  });

  it('rejects the forgery when Encrypt-then-MAC is on', async () => {
    const ballots = await sealBallots(VOTES, keyPair.publicKey, ballotKey);
    // Voter 3 (index 2) voted 0, so dropping the ballot costs the tally nothing
    // and the rigged +100 is the only difference under test.
    const forged = forgeBallot(ballots[2].ciphertext, 100n, keyPair.publicKey);
    ballots[2] = { ...ballots[2], ciphertext: forged.forgedCiphertext, tampered: true };

    const box = await runBallotBox(ballots, keyPair.publicKey, ballotKey, true);

    expect(box.rejected).toHaveLength(1);
    expect(box.rejected[0].voterId).toBe('Voter 3');
    expect(decrypt(box.encryptedTally, keyPair)).toBe(HONEST_TALLY);
  });

  it('accepts every untouched ballot under authentication', async () => {
    const ballots = await sealBallots(VOTES, keyPair.publicKey, ballotKey);
    const box = await runBallotBox(ballots, keyPair.publicKey, ballotKey, true);

    expect(box.rejected).toHaveLength(0);
    expect(decrypt(box.encryptedTally, keyPair)).toBe(HONEST_TALLY);
  });

  it('rejects a ballot re-tagged under a different MAC key', async () => {
    const ballots = await sealBallots([1, 1], keyPair.publicKey, ballotKey);
    const attackerKey = await generateBallotKey();
    const restaged = await sealBallots([1], keyPair.publicKey, attackerKey);
    ballots[1] = { ...restaged[0], voterId: 'Voter 2' };

    const box = await runBallotBox(ballots, keyPair.publicKey, ballotKey, true);
    expect(box.rejected).toHaveLength(1);
  });
});
