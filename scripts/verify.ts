import { gcd, generatePrime, isProbablePrime, lcm, modInverse, modPow } from '../src/numbers';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const generatedPrime = generatePrime(512);

assert(modPow(3n, 100n, 7n) === 4n, 'modPow gate failed');
assert(modInverse(17n, 3120n) === 2753n, 'modInverse gate failed');
assert(gcd(48n, 18n) === 6n, 'gcd gate failed');
assert(lcm(4n, 6n) === 12n, 'lcm gate failed');
assert(isProbablePrime(997n) === true, 'isProbablePrime(997) gate failed');
assert(isProbablePrime(1000n) === false, 'isProbablePrime(1000) gate failed');
assert(generatedPrime.toString(2).length === 512, 'generatePrime bit length gate failed');
assert(isProbablePrime(generatedPrime, 40), 'generatePrime primality gate failed');

console.log('Number theory verification passed.');