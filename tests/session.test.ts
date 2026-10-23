import { describe, expect, it } from 'vitest';
import { isCurrentKeySession } from '../src/session';

describe('key-session authority', () => {
  it('accepts only the epoch and modulus that launched the operation', () => {
    expect(isCurrentKeySession(4, 77n, 4, 77n)).toBe(true);
    expect(isCurrentKeySession(4, 77n, 5, 77n)).toBe(false);
    expect(isCurrentKeySession(4, 77n, 4, 91n)).toBe(false);
    expect(isCurrentKeySession(4, 77n, 4, null)).toBe(false);
  });
});
