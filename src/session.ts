/**
 * Decide whether an asynchronous result still belongs to the key session that
 * launched it. Both the monotonically increasing epoch and modulus are checked:
 * a newly generated key must retire every worker and WebCrypto result from the
 * previous one before that result can regain UI authority.
 */
export function isCurrentKeySession(
  expectedEpoch: number,
  expectedN: bigint,
  currentEpoch: number,
  currentN: bigint | null,
): boolean {
  return expectedEpoch === currentEpoch && expectedN === currentN;
}
