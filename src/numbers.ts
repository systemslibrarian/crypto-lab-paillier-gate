function normalizeMod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}

function abs(value: bigint): bigint {
  return value >= 0n ? value : -value;
}

function bitLength(value: bigint): number {
  if (value < 0n) {
    throw new Error('bitLength requires a non-negative value.');
  }

  if (value === 0n) {
    return 0;
  }

  return value.toString(2).length;
}

function randomBigIntBelow(maxExclusive: bigint): bigint {
  if (maxExclusive <= 0n) {
    throw new Error('maxExclusive must be positive.');
  }

  const bits = bitLength(maxExclusive - 1n);
  const byteLength = Math.max(1, Math.ceil(bits / 8));
  const excessBits = (byteLength * 8) - bits;
  const buffer = new Uint8Array(byteLength);

  while (true) {
    crypto.getRandomValues(buffer);

    if (excessBits > 0) {
      buffer[0] &= 0xff >>> excessBits;
    }

    let candidate = 0n;

    for (const byte of buffer) {
      candidate = (candidate << 8n) | BigInt(byte);
    }

    if (candidate < maxExclusive) {
      return candidate;
    }
  }
}

function randomBigIntWithBits(bits: number): bigint {
  if (!Number.isInteger(bits) || bits <= 1) {
    throw new Error('bits must be an integer greater than 1.');
  }

  const byteLength = Math.ceil(bits / 8);
  const excessBits = (byteLength * 8) - bits;
  const buffer = new Uint8Array(byteLength);

  crypto.getRandomValues(buffer);

  if (excessBits > 0) {
    buffer[0] &= 0xff >>> excessBits;
  }

  const topBitMask = 1 << (7 - excessBits);
  buffer[0] |= topBitMask;
  buffer[buffer.length - 1] |= 0x01;

  let value = 0n;
  for (const byte of buffer) {
    value = (value << 8n) | BigInt(byte);
  }

  return value;
}

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m <= 0n) {
    throw new Error('Modulus must be positive.');
  }

  if (exp < 0n) {
    throw new Error('Exponent must be non-negative.');
  }

  let result = 1n;
  let factor = normalizeMod(base, m);
  let exponent = exp;

  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) {
      result = (result * factor) % m;
    }

    factor = (factor * factor) % m;
    exponent >>= 1n;
  }

  return result;
}

export function extendedGcd(a: bigint, b: bigint): {
  gcd: bigint;
  x: bigint;
  y: bigint;
} {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const quotient = oldR / r;

    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
    [oldT, t] = [t, oldT - quotient * t];
  }

  if (oldR < 0n) {
    return { gcd: -oldR, x: -oldS, y: -oldT };
  }

  return { gcd: oldR, x: oldS, y: oldT };
}

export function modInverse(a: bigint, m: bigint): bigint {
  if (m <= 0n) {
    throw new Error('Modulus must be positive.');
  }

  const { gcd: divisor, x } = extendedGcd(a, m);

  if (divisor !== 1n) {
    throw new Error('Modular inverse does not exist.');
  }

  return normalizeMod(x, m);
}

export function gcd(a: bigint, b: bigint): bigint {
  let left = abs(a);
  let right = abs(b);

  while (right !== 0n) {
    [left, right] = [right, left % right];
  }

  return left;
}

export function lcm(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) {
    return 0n;
  }

  return abs((a / gcd(a, b)) * b);
}

export function randomBigInt(max: bigint): bigint {
  if (max <= 1n) {
    throw new Error('max must be greater than 1.');
  }

  return randomBigIntBelow(max - 1n) + 1n;
}

export function randomCoprime(N: bigint): bigint {
  if (N <= 2n) {
    throw new Error('N must be greater than 2.');
  }

  while (true) {
    const candidate = randomBigInt(N);
    if (gcd(candidate, N) === 1n) {
      return candidate;
    }
  }
}

export function isProbablePrime(n: bigint, k = 40): boolean {
  if (k <= 0) {
    throw new Error('k must be positive.');
  }

  if (n === 2n || n === 3n) {
    return true;
  }

  if (n < 2n || (n & 1n) === 0n) {
    return false;
  }

  let d = n - 1n;
  let s = 0;

  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1;
  }

  witnessLoop: for (let round = 0; round < k; round += 1) {
    const a = randomBigIntBelow(n - 3n) + 2n;
    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) {
      continue;
    }

    for (let i = 1; i < s; i += 1) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        continue witnessLoop;
      }
    }

    return false;
  }

  return true;
}

export function generatePrime(
  bits: number,
  onProgress?: (attempts: number) => void,
): bigint {
  if (!Number.isInteger(bits) || bits < 2) {
    throw new Error('bits must be an integer greater than or equal to 2.');
  }

  let attempts = 0;

  while (true) {
    attempts += 1;
    onProgress?.(attempts);

    const candidate = randomBigIntWithBits(bits);
    if (isProbablePrime(candidate, 40)) {
      return candidate;
    }
  }
}