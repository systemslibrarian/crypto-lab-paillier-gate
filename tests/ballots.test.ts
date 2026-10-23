import { beforeAll, describe, expect, it } from 'vitest';
import {
  forgeBallot,
  generateBallotKey,
  hmacSha256,
  runBallotBox,
  sealBallots,
  tagBallot,
  tagCiphertext,
  tallyBallots,
  verifyBallot,
} from '../src/ballots';
import { decrypt, generateKeyPair, type PaillierKeyPair } from '../src/paillier';
import { RFC4231_HMAC_SHA256 } from './rfc4231-vectors';

/** Hex to bytes, for the published vectors below. */
function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

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

  it('keeps the ballot-box MAC key non-extractable', async () => {
    const key = await generateBallotKey();
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('binds the voter identity as well as the ciphertext', async () => {
    const [ballot] = await sealBallots([1], keyPair.publicKey, ballotKey);
    expect(await verifyBallot({ ...ballot, voterId: 'Voter 2' }, ballotKey)).toBe(false);
    expect(await tagBallot('Voter 1', ballot.ciphertext, ballotKey)).not.toBe(
      await tagBallot('Voter 2', ballot.ciphertext, ballotKey),
    );
  });

  it('treats malformed tags as invalid instead of comparing strings', async () => {
    const [ballot] = await sealBallots([1], keyPair.publicKey, ballotKey);
    expect(await verifyBallot({ ...ballot, tag: 'not hex' }, ballotKey)).toBe(false);
    expect(await verifyBallot({ ...ballot, tag: ballot.tag.slice(2) }, ballotKey)).toBe(false);
    const bent = `${ballot.tag[0] === '0' ? '1' : '0'}${ballot.tag.slice(1)}`;
    expect(await verifyBallot({ ...ballot, tag: bent }, ballotKey)).toBe(false);
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

  it('rejects a replayed voter identity under authentication', async () => {
    const [ballot] = await sealBallots([1], keyPair.publicKey, ballotKey);
    const box = await runBallotBox(
      [ballot, { ...ballot }],
      keyPair.publicKey,
      ballotKey,
      true,
    );

    expect(box.accepted).toHaveLength(1);
    expect(box.rejected).toHaveLength(1);
    expect(decrypt(box.encryptedTally, keyPair)).toBe(1n);
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

describe('HMAC-SHA-256 against RFC 4231', () => {
  /*
   * Every other test in this file goes through `tagCiphertext` on BOTH sides — seal a
   * ballot, verify its tag, tamper with it, verify again — so the hash function and the
   * ciphertext encoding could both have been wrong with all ten of them still green. A
   * round-trip shows the lab agreeing with itself.
   *
   * These assert the lab's own `hmacSha256` against bytes copied from RFC 4231, and
   * they go THROUGH that function rather than calling `crypto.subtle.sign` beside it:
   * in crypto-lab-bike-vault a test written the second way let a mutation switching the
   * lab's digest to SHA-1 pass, because the assertion was testing WebCrypto.
   */
  const importKey = (keyHex: string): Promise<CryptoKey> =>
    crypto.subtle.importKey(
      'raw',
      hexToBytes(keyHex),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );

  it.each(RFC4231_HMAC_SHA256.map((v) => [v.name, v] as const))('%s', async (_name, v) => {
    const key = await importKey(v.keyHex);
    const tag = await hmacSha256(key, hexToBytes(v.dataHex));
    /* Case 5 publishes a 128-bit truncation, so compare the published length. Comparing
       the full digest there would fail a correct implementation; comparing only a prefix
       everywhere would pass a verifier that ignored the tail. */
    expect(tag.slice(0, v.macHex.length)).toBe(v.macHex);
    if (v.macHex.length === 64) expect(tag).toBe(v.macHex);
  });

  it('rejects a one-bit change in the data', async () => {
    const v = RFC4231_HMAC_SHA256[0];
    const key = await importKey(v.keyHex);
    const bent = hexToBytes(v.dataHex);
    bent[0] ^= 0x01;
    expect(await hmacSha256(key, bent)).not.toBe(v.macHex);
  });

  it('rejects a one-bit change in the key', async () => {
    const v = RFC4231_HMAC_SHA256[0];
    const bentKeyHex = (Number.parseInt(v.keyHex.slice(0, 2), 16) ^ 0x01)
      .toString(16)
      .padStart(2, '0') + v.keyHex.slice(2);
    expect(await hmacSha256(await importKey(bentKeyHex), hexToBytes(v.dataHex))).not.toBe(
      v.macHex,
    );
  });

  it('seals ballots under a SHA-256 HMAC key, not merely some HMAC key', async () => {
    /* The vectors above import their OWN key, so they establish that `hmacSha256` is a
       correct HMAC and say nothing about which hash this lab chose for ballots — that
       choice lives in the CryptoKey, not in the function. Switch `generateBallotKey` to
       SHA-1 and every other test in this file still passes, the seven vectors included.
       This is the assertion that notices. */
    const key = await generateBallotKey();
    const algorithm = key.algorithm as HmacKeyAlgorithm;
    expect(algorithm.name).toBe('HMAC');
    expect((algorithm.hash as KeyAlgorithm).name).toBe('SHA-256');
    expect(await tagCiphertext(1n, key)).toHaveLength(64); // 32 bytes, hex
  });

  it('tags a ciphertext as the HMAC of its DECIMAL encoding', async () => {
    /* Pins the encoding `tagCiphertext` chose, which no round-trip can see: both sides
       would move together if it switched to hex, or to big-endian bytes. */
    const key = await generateBallotKey();
    const ciphertext = 1234567890123456789012345678901234567890n;
    const expected = await hmacSha256(key, new TextEncoder().encode(ciphertext.toString()));
    expect(await tagCiphertext(ciphertext, key)).toBe(expected);
    const asHex = await hmacSha256(key, new TextEncoder().encode(ciphertext.toString(16)));
    expect(await tagCiphertext(ciphertext, key)).not.toBe(asHex);
  });
});
