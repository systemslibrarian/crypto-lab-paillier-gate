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
  /** HMAC over a domain-separated voter-id/ciphertext record, hex encoded. */
  tag: string;
  /** True once an attacker has multiplied something into this ciphertext. */
  tampered: boolean;
}

const encoder = new TextEncoder();
const BALLOT_DOMAIN = 'paillier-gate-ballot-v1';

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    return null;
  }

  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function encodeBallot(voterId: string, ciphertext: bigint): Uint8Array<ArrayBuffer> {
  if (!voterId || voterId.includes('\0')) {
    throw new Error('Ballot voterId must be non-empty and must not contain NUL.');
  }

  return encoder.encode(`${BALLOT_DOMAIN}\0${voterId}\0${ciphertext.toString()}`);
}

/** Fresh per-election MAC key held by the ballot box, never by the attacker. */
export async function generateBallotKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

/**
 * HMAC-SHA-256 over arbitrary bytes, hex encoded.
 *
 * Exported so RFC 4231's published vectors can be asserted THROUGH this lab's own MAC
 * rather than against `crypto.subtle` beside it. An assertion on subtle would test
 * WebCrypto and say nothing about this file: in `crypto-lab-bike-vault` exactly that
 * test let a mutation switching the lab's digest to SHA-1 go uncaught.
 *
 * Every test in `tests/ballots.test.ts` before this went through `tagCiphertext` on both
 * sides — seal a ballot, verify the tag, tamper, verify again — so the hash and the
 * encoding could both have been wrong with every one of them still green.
 */
export async function hmacSha256(
  key: CryptoKey,
  /* Uint8Array<ArrayBuffer> rather than a bare Uint8Array: since TypeScript 5.7 the
     typed arrays are generic over their buffer, and `BufferSource` admits only the
     ArrayBuffer instantiation — a bare Uint8Array is Uint8Array<ArrayBufferLike>, which
     could be backed by a SharedArrayBuffer. */
  data: Uint8Array<ArrayBuffer>,
): Promise<string> {
  return toHex(await crypto.subtle.sign('HMAC', key, data));
}

/** HMAC-SHA256 over the decimal encoding of the ciphertext. */
export async function tagCiphertext(ciphertext: bigint, key: CryptoKey): Promise<string> {
  return hmacSha256(key, encoder.encode(ciphertext.toString()));
}

/** Bind a ballot's identity and ciphertext to this exhibit's protocol context. */
export async function tagBallot(
  voterId: string,
  ciphertext: bigint,
  key: CryptoKey,
): Promise<string> {
  return hmacSha256(key, encodeBallot(voterId, ciphertext));
}

/**
 * Verify a ballot's tag over its domain-separated voter identity and current
 * ciphertext with Web Crypto. A changed identity or ciphertext returns false;
 * the page never consults the `tampered` flag to decide.
 */
export async function verifyBallot(ballot: SealedBallot, key: CryptoKey): Promise<boolean> {
  const signature = fromHex(ballot.tag);

  if (!signature) {
    return false;
  }

  try {
    return await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      encodeBallot(ballot.voterId, ballot.ciphertext),
    );
  } catch {
    return false;
  }
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
    const voterId = `Voter ${index + 1}`;
    ballots.push({
      voterId,
      ciphertext,
      tag: await tagBallot(voterId, ciphertext, key),
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
 * invalid tags and repeated voter identifiers are dropped before the tally.
 */
export async function runBallotBox(
  ballots: SealedBallot[],
  publicKey: PaillierPublicKey,
  key: CryptoKey,
  authenticate: boolean,
): Promise<BallotBoxResult> {
  const accepted: SealedBallot[] = [];
  const rejected: SealedBallot[] = [];
  const acceptedVoters = new Set<string>();

  for (const ballot of ballots) {
    if (!authenticate) {
      accepted.push(ballot);
      continue;
    }

    const authentic = await verifyBallot(ballot, key);
    const replayed = acceptedVoters.has(ballot.voterId);

    if (!authentic || replayed) {
      rejected.push(ballot);
      continue;
    }

    acceptedVoters.add(ballot.voterId);
    accepted.push(ballot);
  }

  return { accepted, rejected, encryptedTally: tallyBallots(accepted, publicKey) };
}
