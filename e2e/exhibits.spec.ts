import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the exhibits that make a claim: factoring N and rebuilding
 * λ, the stepped decryption identity, and the ballot malleability attack with
 * and without Encrypt-then-MAC. Every assertion here is on a value the page
 * computed in the browser, including the paths where the attack is supposed to
 * fail.
 */

/**
 * Open the page with motion neutralized.
 *
 * The stepped-decryption exhibit appends a row per step, and the stylesheet
 * uses smooth scrolling plus a hero rise-in animation. Under load the button
 * could still be mid-reflow when Playwright clicked, and the click failed with
 * "element is outside of the viewport" — a layout race, not a defect in the
 * exhibit. Two of three full runs failed this way before this helper existed.
 */
async function open(page: Page): Promise<void> {
  // Ask for reduced motion the way a reader does, rather than forcing it with
  // a style tag. This lab's own `@media (prefers-reduced-motion: reduce)` block
  // already collapses every duration to 0.001ms, so the flake control is
  // identical — but it now comes from the page instead of from the test, which
  // means this suite exercises the rendering a reduced-motion visitor actually
  // gets AND fails if that block ever stops working. Must precede `goto`.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
}

async function generateKey(page: Page, bits: string): Promise<void> {
  await page.selectOption('#bit-length', bits);
  await page.locator('#generate-key').click();
  await expect(page.locator('#metric-bits')).not.toHaveText('-', { timeout: 60_000 });
  await expect(page.locator('#generate-key')).toBeEnabled({ timeout: 60_000 });
}

test.describe('factoring the modulus', () => {
  test('recovers lambda from a 64-bit N and opens the learner ciphertext', async ({ page }) => {
    await open(page);
    await generateKey(page, '64');

    await page.locator('#plaintext-input').fill('4242');
    await page.locator('#encrypt-form button[type="submit"]').click();
    await expect(page.locator('#ciphertext-output')).not.toHaveValue('');

    await page.locator('#factor-key').click();

    const result = page.locator('#factor-result');
    await expect(result).toContainText('Factored.', { timeout: 60_000 });
    await expect(result).toContainText('identical to the private λ generated in the worker');
    await expect(result).toContainText('yields 4242');
    await expect(result).toContainText('the key is broken');
    // The reported work is a measurement, not a caption.
    await expect(result).toContainText(/modular squarings in \d+ ms/);
  });

  test('runs out of budget on a 192-bit N and says so', async ({ page }) => {
    await open(page);
    await generateKey(page, '192');

    await page.locator('#factor-key').click();

    const result = page.locator('#factor-result');
    await expect(result).toContainText('Gave up.', { timeout: 120_000 });
    await expect(result).toContainText(/did not split this 19[12]-bit N/);
    await expect(result).not.toContainText('Factored.');
  });
});

test('steps the decryption identity to the plaintext', async ({ page }) => {
  await open(page);
  await generateKey(page, '64');

  await page.locator('#plaintext-input').fill('777');
  await page.locator('#encrypt-form button[type="submit"]').click();
  await expect(page.locator('#decrypt-input')).not.toHaveValue('');

  for (let step = 1; step <= 4; step += 1) {
    const stepBtn = page.locator('#step-decrypt');
    // Each step appends a row, so the button moves; bring it back into view
    // before clicking rather than relying on the auto-scroll landing settled.
    await stepBtn.scrollIntoViewIfNeeded();
    await stepBtn.click();
    await expect(page.locator('#stepper-list li')).toHaveCount(step);
  }

  const last = page.locator('#stepper-list li').last();
  await expect(last).toContainText('m = L(u) · μ mod N');
  await expect(last).toContainText('decrypt() returns 777');
  await expect(last).toContainText('the stepped identity agrees');
  await expect(last).not.toContainText('MISMATCH');

  // Nothing left to step for this ciphertext.
  await expect(page.locator('#step-decrypt')).toBeDisabled();

  await page.locator('#reset-stepper').click();
  await expect(page.locator('#stepper-list li')).toHaveCount(0);
});

test.describe('ballot malleability', () => {
  test('an unauthenticated ballot box accepts a rigged tally', async ({ page }) => {
    await open(page);
    await generateKey(page, '64');

    await page.locator('#election-form button[type="submit"]').click();
    await expect(page.locator('#election-result')).toContainText('Honest tally decrypts to 6 / 10');
    await expect(page.locator('#election-result')).toContainText('match');
    await expect(page.locator('#ballot-list li')).toHaveCount(10);

    await expect(page.locator('#attack-authenticate')).not.toBeChecked();
    await page.locator('#attack-target').selectOption('0');
    await page.locator('#attack-boost').fill('100');
    await page.locator('#forge-ballot').click();

    const result = page.locator('#attack-result');
    await expect(result).toContainText('The tally is rigged.');
    await expect(result).toContainText('now decrypts to 106');
    await expect(result).toContainText('+100 against the honest 6');
    await expect(result).toContainText('accepted all 10 ballots');
    await expect(page.locator('#ballot-list li').first()).toContainText('rewritten in transit');
  });

  test('Encrypt-then-MAC rejects the same forged ballot', async ({ page }) => {
    await open(page);
    await generateKey(page, '64');

    await page.locator('#election-form button[type="submit"]').click();
    await expect(page.locator('#election-result')).toContainText('Honest tally decrypts to 6 / 10');

    await page.locator('#attack-authenticate').check();
    // Voter 3 votes 0 in the default ballot, so the honest tally is unchanged
    // when the box drops the forged ballot.
    await page.locator('#attack-target').selectOption('2');
    await page.locator('#attack-boost').fill('100');
    await page.locator('#forge-ballot').click();

    const result = page.locator('#attack-result');
    await expect(result).toContainText('Encrypt-then-MAC caught it.');
    await expect(result).toContainText('1 ballot(s) rejected, 9 counted');
    await expect(result).toContainText('decrypts to 6');
    await expect(result).not.toContainText('The tally is rigged.');
  });

  test('a fresh keypair clears the ballot box', async ({ page }) => {
    await open(page);
    await generateKey(page, '64');
    await page.locator('#election-form button[type="submit"]').click();
    await expect(page.locator('#ballot-attack')).toBeVisible();

    await generateKey(page, '64');
    await expect(page.locator('#ballot-attack')).toBeHidden();
    await expect(page.locator('#forge-ballot')).toBeDisabled();
  });
});

test('weighted aggregation reports both homomorphisms against the plaintext arithmetic', async ({ page }) => {
  await open(page);
  await generateKey(page, '96');

  await page.locator('#aggregation-form button[type="submit"]').click();

  const result = page.locator('#aggregation-result');
  // 10+25+17+8+30 = 90; 1*10+2*25+3*17+4*8+5*30 = 293.
  await expect(result).toContainText('decrypts to 90');
  await expect(result).toContainText('Σxᵢ = 90 — match');
  await expect(result).toContainText('decrypts to 293');
  await expect(result).toContainText('Σwᵢxᵢ = 293 — match');
  await expect(result).not.toContainText('mismatch');
  await expect(page.locator('#aggregation-rows tr')).toHaveCount(5);
});
