import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * A real Paillier keypair is generated and every exhibit downstream of it is
 * driven — including both branches of the ballot-malleability attack — with
 * each resulting rendering scanned in both themes at desktop and phone width.
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}

/**
 * The non-text baseline's third rule, which had never run.
 *
 * `nontext-baseline.ts` claims three: a finding not listed fails, a listed
 * finding that got WORSE fails, and a listed finding that has been FIXED fails
 * until its entry is deleted. The first two live in
 * `expectNoNewNonTextFailures` and fire from every `scan` above. The third is
 * `expectBaselineNotStale`, which was exported and never imported — so the
 * baseline could only ever grow.
 *
 * It gets its own test, driving BOTH themes itself, and that is the whole
 * point rather than a tidiness preference. The baseline is keyed by selector
 * alone, so it is a UNION over the themes — and the four `.button` entries are
 * light-theme findings: measured through the gate's own capture path, the
 * boundary of `#generate-key`, `#factor-key`, `#forge-ballot` and `button.button`
 * clears 3:1 against the dark surface and only fails against the light one
 * (1.89-2.02:1). `nonTextSeen` is module state, so a call tacked onto the
 * per-theme tests asks the dark worker about findings only the light worker can
 * see, and it reported all four as stale on every run. That was measured, not
 * assumed, and it is a false stale: nothing has been fixed. Only a pass that
 * covers both themes can decide the question the rule actually asks.
 */
test('the non-text baseline has no stale entries', async ({ page }) => {
  test.setTimeout(900_000);
  for (const theme of ['dark', 'light'] as const) {
    await boot(page, theme);
    await driveAllStates(page, `stale sweep / ${theme}`);
  }
  expectBaselineNotStale();
});
