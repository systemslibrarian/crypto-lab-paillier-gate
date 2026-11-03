export const MAX_DECIMAL_DIGITS = 256;
export const MAX_AGGREGATION_VALUES = 50;
export const MAX_VOTES = 100;

function splitList(value: string, fieldName: string, maxValues: number): string[] {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${fieldName} must contain at least one value.`);
  }

  const parts = trimmed.split(',').map((part) => part.trim());

  if (parts.some((part) => part === '')) {
    throw new Error(`${fieldName} must not contain an empty entry.`);
  }

  if (parts.length > maxValues) {
    throw new Error(`${fieldName} must contain at most ${maxValues} values.`);
  }

  return parts;
}

export function parseNonNegativeBigInt(
  value: string,
  fieldName: string,
  maxDigits = MAX_DECIMAL_DIGITS,
): bigint {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${fieldName} is required.`);
  }

  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${fieldName} must be a non-negative decimal integer.`);
  }

  if (trimmed.length > maxDigits) {
    throw new Error(`${fieldName} must be at most ${maxDigits} decimal digits.`);
  }

  return BigInt(trimmed);
}

export function parseBigIntList(
  value: string,
  fieldName: string,
  maxValues = MAX_AGGREGATION_VALUES,
): bigint[] {
  return splitList(value, fieldName, maxValues).map((part, index) =>
    parseNonNegativeBigInt(part, `${fieldName} #${index + 1}`),
  );
}

export function parseOptionalWeights(value: string, count: number): bigint[] {
  if (value.trim() === '') {
    return Array.from({ length: count }, () => 1n);
  }

  const weights = parseBigIntList(value, 'Weights', MAX_AGGREGATION_VALUES);

  if (weights.length !== count) {
    throw new Error(`Weights must contain exactly ${count} values, or be left blank.`);
  }

  return weights;
}

export function parseVoteList(value: string): number[] {
  return splitList(value, 'Votes', MAX_VOTES).map((part, index) => {
    if (part !== '0' && part !== '1') {
      throw new Error(`Vote #${index + 1} must be 0 or 1.`);
    }

    return Number(part);
  });
}
