/// <reference types="vite/client" />
import { describe, it, expect } from 'vitest';

import mainSource from '../src/main.ts?raw';

/**
 * `setResultBox` writes its argument to `innerHTML` because every success
 * message in this lab is markup — `<strong>`, `<code>`, `<em>`. Every FAILURE
 * message is an exception's text, and exception text quotes what the visitor
 * typed: `BigInt('<img src=x onerror=…>')` throws "Cannot convert <img
 * src=x onerror=…> to a BigInt". Routing that through `setResultBox` put it
 * into `innerHTML` as markup — CodeQL `js/xss-through-exception`, whose flow
 * ran from `plaintextInput.value` through `parseNonNegativeBigInt`'s throw to
 * `element.innerHTML`.
 *
 * `setResultText` writes `textContent`, which has no markup door. This asserts
 * the WIRING rather than the helper: a helper test would stay green if a
 * future error path were pointed back at the HTML one, which is the mistake
 * worth catching.
 */
const source: string = mainSource;

/** Every `setResultBox(` / `setResultText(` call, by bracket matching. */
function calls(text: string, name: string): string[] {
  const found: string[] = [];
  for (let at = text.indexOf(`${name}(`); at !== -1; at = text.indexOf(`${name}(`, at + 1)) {
    if (/function\s+$/.test(text.slice(Math.max(0, at - 10), at))) continue;
    let depth = 0;
    for (let i = at + name.length; i < text.length; i += 1) {
      if (text[i] === '(') depth += 1;
      else if (text[i] === ')') {
        depth -= 1;
        if (depth === 0) {
          found.push(text.slice(at, i + 1));
          break;
        }
      }
    }
  }
  return found;
}

/** Text that came out of a caught exception, however the caller spells it. */
const EXCEPTION_TEXT = /\berror\s*instanceof\s*Error\b|\berror\.message\b|\bmessage\.message\b/;

describe('exception text never reaches the markup door', () => {
  it('finds both families of call site', () => {
    // A scan that matched nothing would pass the rule below over nothing.
    expect(calls(source, 'setResultBox').length).toBeGreaterThanOrEqual(20);
    expect(calls(source, 'setResultText').length).toBeGreaterThanOrEqual(10);
  });

  it('routes no exception message through setResultBox', () => {
    const offenders = calls(source, 'setResultBox').filter((c) => EXCEPTION_TEXT.test(c));
    expect(offenders, `these put exception text into innerHTML:\n${offenders.join('\n')}`).toEqual([]);
  });

  it('catches an exception message routed through setResultBox', () => {
    // The positive control: the rule above is only worth having if it fails.
    const offender = "setResultBox(decryptResult, error instanceof Error ? error.message : 'Encryption failed.', 'error')";
    const found = calls(offender, 'setResultBox');
    expect(found).toHaveLength(1);
    expect(EXCEPTION_TEXT.test(found[0])).toBe(true);
  });

  it('writes error text with textContent and never innerHTML', () => {
    const body = source.slice(source.indexOf('function setResultText'));
    const definition = body.slice(0, body.indexOf('\n}\n') + 2);
    expect(definition).toContain('element.textContent = text;');
    expect(definition).not.toContain('innerHTML');
  });
});
