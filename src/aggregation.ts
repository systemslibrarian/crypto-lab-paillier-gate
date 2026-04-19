import { addCiphertexts, encrypt, multiplyByScalar, type PaillierPublicKey } from './paillier';

export interface HospitalData {
  id: string;
  privateCount: bigint;
  encryptedCount: bigint;
}

export interface Vote {
  voterId: string;
  encryptedVote: bigint;
}

export function simulatePrivateAggregation(
  privateCounts: bigint[],
  publicKey: PaillierPublicKey,
): {
  hospitals: HospitalData[];
  encryptedTotal: bigint;
} {
  const hospitals = privateCounts.map((privateCount, index) => {
    const { ciphertext } = encrypt(privateCount, publicKey);
    return {
      id: `Hospital ${String.fromCharCode(65 + index)}`,
      privateCount,
      encryptedCount: ciphertext,
    };
  });

  const encryptedTotal = hospitals.reduce((accumulator, hospital) => {
    return addCiphertexts(accumulator, hospital.encryptedCount, publicKey);
  }, 1n);

  return { hospitals, encryptedTotal };
}

export function simulatePrivateElection(
  votes: number[],
  publicKey: PaillierPublicKey,
): {
  encryptedVotes: Vote[];
  encryptedTally: bigint;
} {
  const encryptedVotes = votes.map((vote, index) => {
    if (vote !== 0 && vote !== 1) {
      throw new Error('Votes must be 0 or 1.');
    }

    const { ciphertext } = encrypt(BigInt(vote), publicKey);
    return {
      voterId: `Voter ${index + 1}`,
      encryptedVote: ciphertext,
    };
  });

  const encryptedTally = encryptedVotes.reduce((accumulator, vote) => {
    return addCiphertexts(accumulator, vote.encryptedVote, publicKey);
  }, 1n);

  return { encryptedVotes, encryptedTally };
}

export function weightedSum(
  encryptedValues: bigint[],
  weights: bigint[],
  publicKey: PaillierPublicKey,
): bigint {
  if (encryptedValues.length !== weights.length) {
    throw new Error('encryptedValues and weights must have the same length.');
  }

  return encryptedValues.reduce((accumulator, ciphertext, index) => {
    const weightedCiphertext = multiplyByScalar(ciphertext, weights[index], publicKey);
    return addCiphertexts(accumulator, weightedCiphertext, publicKey);
  }, 1n);
}