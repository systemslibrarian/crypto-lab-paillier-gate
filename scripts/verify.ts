import { simulatePrivateAggregation, simulatePrivateElection, weightedSum } from '../src/aggregation';
import { gcd, generatePrime, isProbablePrime, lcm, modInverse, modPow } from '../src/numbers';
import {
  addCiphertexts,
  addPlaintext,
  decrypt,
  encrypt,
  generateKeyPair,
  multiplyByScalar,
  rerandomize,
} from '../src/paillier';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function main(): Promise<void> {
  const generatedPrime = generatePrime(512);

  assert(modPow(3n, 100n, 7n) === 4n, 'modPow gate failed');
  assert(modInverse(17n, 3120n) === 2753n, 'modInverse gate failed');
  assert(gcd(48n, 18n) === 6n, 'gcd gate failed');
  assert(lcm(4n, 6n) === 12n, 'lcm gate failed');
  assert(isProbablePrime(997n) === true, 'isProbablePrime(997) gate failed');
  assert(isProbablePrime(1000n) === false, 'isProbablePrime(1000) gate failed');
  assert(generatedPrime.toString(2).length === 512, 'generatePrime bit length gate failed');
  assert(isProbablePrime(generatedPrime, 40), 'generatePrime primality gate failed');

  const toyKeyPair = await generateKeyPair(12);
  const toy42 = encrypt(42n, toyKeyPair.publicKey);
  assert(decrypt(toy42.ciphertext, toyKeyPair) === 42n, 'Toy round-trip gate failed');

  const toy7 = encrypt(7n, toyKeyPair.publicKey);
  const toy13 = encrypt(13n, toyKeyPair.publicKey);
  assert(
    decrypt(addCiphertexts(toy7.ciphertext, toy13.ciphertext, toyKeyPair.publicKey), toyKeyPair) === 20n,
    'Homomorphic addition gate failed',
  );

  const toy10 = encrypt(10n, toyKeyPair.publicKey);
  assert(
    decrypt(addPlaintext(toy10.ciphertext, 5n, toyKeyPair.publicKey), toyKeyPair) === 15n,
    'Plaintext addition gate failed',
  );

  const toy6 = encrypt(6n, toyKeyPair.publicKey);
  assert(
    decrypt(multiplyByScalar(toy6.ciphertext, 7n, toyKeyPair.publicKey), toyKeyPair) === 42n,
    'Scalar multiplication gate failed',
  );

  const encryptTwiceA = encrypt(42n, toyKeyPair.publicKey);
  const encryptTwiceB = encrypt(42n, toyKeyPair.publicKey);
  assert(
    encryptTwiceA.ciphertext !== encryptTwiceB.ciphertext,
    'Randomized encryption gate failed',
  );

  const rerandomized = rerandomize(encryptTwiceA.ciphertext, toyKeyPair.publicKey);
  assert(decrypt(rerandomized, toyKeyPair) === 42n, 'Rerandomization gate failed');

  const productionKeyPair = await generateKeyPair(2048);
  const productionMessage = 1234567890n;
  const productionCiphertext = encrypt(productionMessage, productionKeyPair.publicKey);
  assert(
    decrypt(productionCiphertext.ciphertext, productionKeyPair) === productionMessage,
    'Production round-trip gate failed',
  );

  const hundredValues = Array.from({ length: 100 }, (_, index) => BigInt(index + 1));
  const encryptedHundredValues = hundredValues.map((value) => encrypt(value, productionKeyPair.publicKey).ciphertext);
  const encryptedSum = encryptedHundredValues.reduce((accumulator, ciphertext) => {
    return addCiphertexts(accumulator, ciphertext, productionKeyPair.publicKey);
  }, 1n);
  const expectedSum = hundredValues.reduce((accumulator, value) => accumulator + value, 0n) % productionKeyPair.publicKey.N;
  assert(decrypt(encryptedSum, productionKeyPair) === expectedSum, '100-element homomorphic sum gate failed');

  const hospitalScenario = simulatePrivateAggregation([10n, 25n, 17n, 8n, 30n], toyKeyPair.publicKey);
  assert(decrypt(hospitalScenario.encryptedTotal, toyKeyPair) === 90n, 'Hospital aggregation gate failed');

  const electionScenario = simulatePrivateElection([1, 1, 0, 1, 0, 1, 0, 1, 1, 0], toyKeyPair.publicKey);
  assert(decrypt(electionScenario.encryptedTally, toyKeyPair) === 6n, 'Election tally gate failed');

  const weightedCiphertext = weightedSum(
    [10n, 20n, 30n].map((value) => encrypt(value, toyKeyPair.publicKey).ciphertext),
    [1n, 2n, 3n],
    toyKeyPair.publicKey,
  );
  assert(decrypt(weightedCiphertext, toyKeyPair) === 140n, 'Weighted sum gate failed');

  console.log('All verification gates passed.');
}

void main();