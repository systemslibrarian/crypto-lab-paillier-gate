import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. In particular the ballot
 *     attack block is `hidden` until the tally has run; force-revealing it, as
 *     the replaced gate's `[hidden]`-stripping did, scans an empty attack panel
 *     dressed as a populated one.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. Every exhibit here is gated on a real Paillier keypair
 *     generated in a Web Worker — most controls stay `disabled` until it lands
 *     — so a gate that does not wait for it measures a page of disabled buttons
 *     and empty output panels.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#generate-key')).toBeVisible();
  await expect(page.locator('#key-form')).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: Paillier ciphertexts are 2048-bit integers printed in
 * full, and the ledger lays out on a `minmax(160px, 220px)` track.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element, which is
    // exactly what happened here: the 980px comparison table was reported while
    // the real overflow was 15px of something else entirely.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const widest = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .filter((x) => !clipped(x.el))
      .sort((a, b) => b.r.right - a.r.right)[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}


/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Everything downstream of the keypair is disabled until the worker returns, so
 * the keypair is generated first and waited for properly rather than slept on.
 * Both branches are driven where an exhibit has them — notably the ballot
 * attack, whose whole point is the difference between an unauthenticated forge
 * that succeeds and an authenticated one that does not.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // Real Paillier keygen in a Web Worker; the metrics panel filling is the
  // signal it landed, and everything else is disabled until then.
  await page.locator('#generate-key').click();
  await expect(page.locator('#metric-n')).not.toBeEmpty({ timeout: 180_000 });
  await expect(page.locator('#encrypt-form button[type="submit"]').first()).toBeEnabled({
    timeout: 180_000,
  });
  await scan(page, `${theme} / keypair generated`);

  // Encrypt, then re-encrypt the same plaintext and re-randomise — the semantic
  // security exhibit: same m, different c every time.
  await page.locator('#plaintext-input').fill('42');
  await page.locator('#encrypt-form button[type="submit"]').first().click();
  await expect(page.locator('#ciphertext-output')).not.toBeEmpty();
  await scan(page, `${theme} / encrypted`);

  await page.locator('#encrypt-again').click();
  await expect(page.locator('#semantic-list')).not.toBeEmpty();
  await scan(page, `${theme} / encrypted again (same m)`);

  await page.locator('#rerandomize').click();
  await expect(page.locator('#randomizer-output')).not.toBeEmpty();
  await scan(page, `${theme} / re-randomised`);

  // Decrypt, including the stepped walkthrough.
  await page.locator('#decrypt-form button[type="submit"]').first().click();
  await expect(page.locator('#decrypt-result')).not.toBeEmpty();
  await scan(page, `${theme} / decrypted`);

  await page.locator('#step-decrypt').click();
  await expect(page.locator('#stepper-list')).not.toBeEmpty();
  await scan(page, `${theme} / decrypt stepped`);

  // The homomorphic sum, and the modulus-overflow preset that breaks it.
  await page.locator('#sum-form button[type="submit"]').first().click();
  await expect(page.locator('#sum-result')).not.toBeEmpty();
  await scan(page, `${theme} / homomorphic sum`);

  await page.locator('#overflow-preset').click();
  await expect(page.locator('#sum-result')).not.toBeEmpty();
  await scan(page, `${theme} / modulus overflow`);

  // Ledger slots.
  await page.locator('#add-to-ledger').click();
  await page.locator('#ledger-decrypt').waitFor();
  await scan(page, `${theme} / ledger`);

  // The election: seal and tally, then the weighted aggregation.
  await page.locator('#election-form button[type="submit"]').first().click();
  await expect(page.locator('#election-result')).not.toBeEmpty();
  await scan(page, `${theme} / election tallied`);

  await page.locator('#aggregation-form button[type="submit"]').first().click();
  await expect(page.locator('#aggregation-result')).not.toBeEmpty();
  await scan(page, `${theme} / weighted aggregation`);

  // The ballot attack, both branches: malleability succeeds unauthenticated,
  // and is caught once the ballots are authenticated.
  await expect(page.locator('#ballot-attack')).toBeVisible();
  await page.locator('#attack-boost').fill('100');
  await page.locator('#forge-ballot').click();
  await expect(page.locator('#attack-result')).not.toBeEmpty();
  await scan(page, `${theme} / ballot forged`);

  await page.locator('#attack-authenticate').check();
  await page.locator('#forge-ballot').click();
  await expect(page.locator('#attack-result')).not.toBeEmpty();
  await scan(page, `${theme} / ballot forge rejected`);

  // The factoring exhibit: a bounded attempt on the modulus.
  await page.locator('#factor-key').click();
  await expect(page.locator('#factor-result')).not.toBeEmpty({ timeout: 180_000 });
  await scan(page, `${theme} / factoring attempt`);
}
