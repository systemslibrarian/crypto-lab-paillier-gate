import { describe, expect, it } from 'vitest';
import {
  MAX_AGGREGATION_VALUES,
  MAX_DECIMAL_DIGITS,
  MAX_VOTES,
  parseBigIntList,
  parseNonNegativeBigInt,
  parseOptionalWeights,
  parseVoteList,
} from '../src/input';

describe('bounded decimal inputs', () => {
  it('accepts bounded non-negative decimal integers', () => {
    expect(parseNonNegativeBigInt(' 0042 ', 'Message')).toBe(42n);
    expect(parseNonNegativeBigInt('0', 'Message')).toBe(0n);
  });

  it('rejects signs, non-decimal text, and oversized integers', () => {
    expect(() => parseNonNegativeBigInt('-1', 'Message')).toThrow(/non-negative decimal/);
    expect(() => parseNonNegativeBigInt('+1', 'Message')).toThrow(/non-negative decimal/);
    expect(() => parseNonNegativeBigInt('1e6', 'Message')).toThrow(/non-negative decimal/);
    expect(() =>
      parseNonNegativeBigInt('9'.repeat(MAX_DECIMAL_DIGITS + 1), 'Message'),
    ).toThrow(/at most 256/);
  });

  it('rejects empty list entries and oversized aggregation workloads', () => {
    expect(() => parseBigIntList('1,,2', 'Counts')).toThrow(/empty entry/);
    expect(() =>
      parseBigIntList(Array.from({ length: MAX_AGGREGATION_VALUES + 1 }, () => '1').join(','), 'Counts'),
    ).toThrow(/at most 50/);
  });
});

describe('optional weights', () => {
  it('defaults every omitted weight to one', () => {
    let weights: bigint[] | undefined;
    expect(() => {
      weights = parseOptionalWeights('   ', 3);
    }).not.toThrow();
    expect(weights).toEqual([1n, 1n, 1n]);
  });

  it('requires an explicit list to match the count list exactly', () => {
    expect(parseOptionalWeights('1, 2, 3', 3)).toEqual([1n, 2n, 3n]);
    expect(() => parseOptionalWeights('1, 2', 3)).toThrow(/exactly 3/);
  });
});

describe('vote workloads', () => {
  it('accepts only bounded binary lists', () => {
    expect(parseVoteList('1, 0, 1')).toEqual([1, 0, 1]);
    expect(() => parseVoteList('1, 2')).toThrow(/0 or 1/);
    expect(() =>
      parseVoteList(Array.from({ length: MAX_VOTES + 1 }, () => '0').join(',')),
    ).toThrow(/at most 100/);
  });
});
