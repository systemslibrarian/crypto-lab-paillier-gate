import { generatePrime, gcd, lcm, modInverse, modPow, randomCoprime } from './numbers';

export interface PaillierPublicKey {
  N: bigint;
  g: bigint;
  N2: bigint;
  bitLength: number;
}

export interface PaillierPrivateKey {
  lambda: bigint;
  mu: bigint;
  p: bigint;
  q: bigint;
}

export interface PaillierKeyPair {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
}

function bigintBitLength(value: bigint): number {
  if (value <= 0n) {
    return 0;
  }

  return value.toString(2).length;
}

function normalizeMod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

function assertPlaintextInRange(message: bigint, N: bigint): void {
  if (message < 0n) {
    throw new Error('Plaintext must be non-negative.');
  }

  if (message >= N) {
    throw new Error('Plaintext must be less than N.');
  }
}

export async function generateKeyPair(
  bitLength: number,
  onProgress?: (stage: string, percent: number) => void,
): Promise<PaillierKeyPair> {
  if (!Number.isInteger(bitLength) || bitLength < 12) {
    throw new Error('bitLength must be an integer greater than or equal to 12.');
  }

  const primeBits = Math.floor(bitLength / 2);
  let pAttempts = 0;
  let qAttempts = 0;

  onProgress?.(`Searching for prime p (${primeBits} bits)...`, 5);
  const p = generatePrime(primeBits, (attempts) => {
    pAttempts = attempts;
    onProgress?.(`Searching for prime p (${primeBits} bits)... attempt ${attempts}`, 10);
  });
  await yieldToEventLoop();

  onProgress?.(`Searching for prime q (${primeBits} bits)...`, 30);
  let q = generatePrime(primeBits, (attempts) => {
    qAttempts = attempts;
    onProgress?.(`Searching for prime q (${primeBits} bits)... attempt ${attempts}`, 35);
  });

  while (q === p) {
    onProgress?.(`Prime q matched p; regenerating q... attempt ${qAttempts + 1}`, 40);
    q = generatePrime(primeBits, (attempts) => {
      qAttempts = attempts;
      onProgress?.(`Searching for prime q (${primeBits} bits)... attempt ${attempts}`, 42);
    });
  }

  await yieldToEventLoop();

  const N = p * q;
  const lambda = lcm(p - 1n, q - 1n);

  if (gcd(lambda, N) !== 1n) {
    throw new Error('Invalid key material: lambda is not invertible mod N.');
  }

  const g = N + 1n;
  const N2 = N * N;

  onProgress?.(`Computing modulus N = p · q (${bigintBitLength(N)} bits)`, 65);
  await yieldToEventLoop();

  onProgress?.('Computing lambda = lcm(p-1, q-1)', 78);
  const mu = modInverse(lambda, N);
  await yieldToEventLoop();

  onProgress?.('Computing mu = lambda^-1 mod N', 90);
  onProgress?.(`Keypair generated. p attempts: ${pAttempts}, q attempts: ${qAttempts}`, 100);

  return {
    publicKey: {
      N,
      g,
      N2,
      bitLength: bigintBitLength(N),
    },
    privateKey: {
      lambda,
      mu,
      p,
      q,
    },
  };
}

export function encrypt(
  message: bigint,
  publicKey: PaillierPublicKey,
): { ciphertext: bigint; r: bigint } {
  assertPlaintextInRange(message, publicKey.N);

  const r = randomCoprime(publicKey.N);
  const gm = modPow(publicKey.g, message, publicKey.N2);
  const rToN = modPow(r, publicKey.N, publicKey.N2);

  return {
    ciphertext: (gm * rToN) % publicKey.N2,
    r,
  };
}

export function L(x: bigint, N: bigint): bigint {
  const numerator = x - 1n;

  if (numerator % N !== 0n) {
    throw new Error('L(x) requires (x - 1) to be divisible by N.');
  }

  return numerator / N;
}

export function decrypt(
  ciphertext: bigint,
  keyPair: PaillierKeyPair,
): bigint {
  const {
    publicKey: { N, N2 },
    privateKey: { lambda, mu },
  } = keyPair;

  const normalizedCiphertext = normalizeMod(ciphertext, N2);
  const u = modPow(normalizedCiphertext, lambda, N2);
  const lValue = L(u, N);

  return normalizeMod(lValue * mu, N);
}

export function addCiphertexts(
  c1: bigint,
  c2: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  return normalizeMod(c1, publicKey.N2) * normalizeMod(c2, publicKey.N2) % publicKey.N2;
}

export function addPlaintext(
  ciphertext: bigint,
  plaintext: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  assertPlaintextInRange(normalizeMod(plaintext, publicKey.N), publicKey.N);
  const encodedPlaintext = modPow(publicKey.g, normalizeMod(plaintext, publicKey.N), publicKey.N2);
  return addCiphertexts(ciphertext, encodedPlaintext, publicKey);
}

export function multiplyByScalar(
  ciphertext: bigint,
  scalar: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  const normalizedScalar = normalizeMod(scalar, publicKey.N);
  return modPow(normalizeMod(ciphertext, publicKey.N2), normalizedScalar, publicKey.N2);
}

export function rerandomize(
  ciphertext: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  const freshFactor = modPow(randomCoprime(publicKey.N), publicKey.N, publicKey.N2);
  return addCiphertexts(ciphertext, freshFactor, publicKey);
}