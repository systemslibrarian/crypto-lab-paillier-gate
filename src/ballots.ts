import { addCiphertexts, encrypt, type PaillierPublicKey } from './paillier';

/**
 * Ballot handling for the election scenario, including the malleability attack
 * that additive homomorphism hands to anyone holding a ciphertext.
 *
 * The attacker functions here take a `PaillierPublicKey` and nothing else. That
 * is the claim the page makes — "rewritten with the public key alone" — enforced
 * by the signature rather than by a caption.
 */

export interface SealedBallot {
  voterId: string;
  ciphertext: bigint;
  /** Encrypt-then-MAC tag over the ciphertext bytes, hex encoded. */
  tag: string;
  /** True once an attacker has multiplied something into this ciphertext. */
  tampered: boolean;
}

const encoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/** Fresh per-election MAC key held by the ballot box, never by the attacker. */
export async function generateBallotKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
}

/** HMAC-SHA256 over the decimal encoding of the ciphertext. */
export async function tagCiphertext(ciphertext: bigint, key: CryptoKey): Promise<string> {
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(ciphertext.toString()));
  return toHex(signature);
}

/**
 * Verify a ballot's tag by recomputing it over the ciphertext as it stands now.
 * A tampered ciphertext produces a different tag, so this returns false — the
 * page never consults the `tampered` flag to decide.
 */
export async function verifyBallot(ballot: SealedBallot, key: CryptoKey): Promise<boolean> {
  const expected = await tagCiphertext(ballot.ciphertext, key);
  return expected === ballot.tag;
}

export async function sealBallots(
  votes: number[],
  publicKey: PaillierPublicKey,
  key: CryptoKey,
): Promise<SealedBallot[]> {
  const ballots: SealedBallot[] = [];

  for (const [index, vote] of votes.entries()) {
    if (vote !== 0 && vote !== 1) {
      throw new Error(`Vote #${index + 1} must be 0 or 1.`);
    }

    const { ciphertext } = encrypt(BigInt(vote), publicKey);
    ballots.push({
      voterId: `Voter ${index + 1}`,
      ciphertext,
      tag: await tagCiphertext(ciphertext, key),
      tampered: false,
    });
  }

  return ballots;
}

/** Multiply every ballot together mod N² — the encrypted tally. */
export function tallyBallots(ballots: SealedBallot[], publicKey: PaillierPublicKey): bigint {
  return ballots.reduce(
    (accumulator, ballot) => addCiphertexts(accumulator, ballot.ciphertext, publicKey),
    1n,
  );
}

export interface ForgedBallot {
  /** Enc(boost), produced by the attacker with the public key. */
  injectedCiphertext: bigint;
  /** The victim's ciphertext times Enc(boost) mod N². */
  forgedCiphertext: bigint;
}

/**
 * The malleability attack. The attacker encrypts `boost` under the *public* key
 * and multiplies it into a ballot they intercepted. They never learn the vote
 * and never touch λ — but the tally now decrypts `boost` higher.
 */
export function forgeBallot(
  ciphertext: bigint,
  boost: bigint,
  publicKey: PaillierPublicKey,
): ForgedBallot {
  if (boost < 0n) {
    throw new Error('Boost must be non-negative.');
  }

  const injected = encrypt(boost, publicKey);

  return {
    injectedCiphertext: injected.ciphertext,
    forgedCiphertext: addCiphertexts(ciphertext, injected.ciphertext, publicKey),
  };
}

export interface BallotBoxResult {
  accepted: SealedBallot[];
  rejected: SealedBallot[];
  encryptedTally: bigint;
}

/**
 * What the ballot box does on receipt. With `authenticate` off it simply
 * multiplies everything it was handed — the attack goes through. With it on,
 * every tag is recomputed and mismatching ballots are dropped before the tally.
 */
export async function runBallotBox(
  ballots: SealedBallot[],
  publicKey: PaillierPublicKey,
  key: CryptoKey,
  authenticate: boolean,
): Promise<BallotBoxResult> {
  const accepted: SealedBallot[] = [];
  const rejected: SealedBallot[] = [];

  for (const ballot of ballots) {
    if (!authenticate || (await verifyBallot(ballot, key))) {
      accepted.push(ballot);
    } else {
      rejected.push(ballot);
    }
  }

  return { accepted, rejected, encryptedTally: tallyBallots(accepted, publicKey) };
}
