import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the CLI verify vectors;
 * this gates them on accessibility the same way. Drives the live demo so that
 * dynamically-injected result regions are scanned, and scans both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animations/transitions/opacity so a mid-fade frame can't produce
// phantom contrast failures, and expand every native <details> (none here, but
// future-proof).
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      transition-duration: 0s !important;
      transition-delay: 0s !important;
    }`,
  });
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

// Generate a keypair (unlocks the disabled demo buttons) and exercise every
// form so all async result regions render their populated state, then scan.
async function driveDemo(page: Page): Promise<void> {
  // Smallest key size for speed.
  await page.selectOption('#bit-length', '64');
  await page.locator('#generate-key').click();
  await expect(page.locator('#metric-bits')).not.toHaveText('-', { timeout: 60_000 });
  await expect(page.locator('#generate-key')).toBeEnabled({ timeout: 60_000 });

  await page.locator('#encrypt-form button[type="submit"]').click();
  await expect(page.locator('#ciphertext-output')).not.toHaveValue('');

  // Exercise the "same message, different ciphertext" semantic-security stack so
  // its dynamically-added rows get scanned.
  await page.locator('#encrypt-again').click();
  await expect(page.locator('#semantic-list li')).toHaveCount(2);

  // Hand the learner's own ciphertext into Step 3 slot A.
  await page.locator('#add-to-ledger').click();

  await page.locator('#decrypt-form button[type="submit"]').click();
  await expect(page.locator('#decrypt-result')).toContainText('Decrypted value');

  await page.locator('#sum-form button[type="submit"]').click();
  await expect(page.locator('#sum-result')).toContainText('decrypts to');
  // The homomorphic-addition ledger and multiply->add insight are now visible.
  await expect(page.locator('#sum-ledger')).toBeVisible();
  await expect(page.locator('#sum-insight')).toBeVisible();

  // Trigger the overflow demonstration so its error-tone result region is scanned.
  await page.locator('#overflow-preset').click();
  await page.locator('#sum-form button[type="submit"]').click();
  await expect(page.locator('#sum-result')).toContainText('overflow');

  await page.locator('#aggregation-form button[type="submit"]').click();
  await expect(page.locator('#aggregation-result')).toContainText('decrypts to');
  await expect(page.locator('#aggregation-table')).toBeVisible();

  // Ballot scenario plus the malleability attack, so the ballot list and the
  // attack result region are both populated when axe runs.
  await page.locator('#election-form button[type="submit"]').click();
  await expect(page.locator('#election-result')).toContainText('Honest tally');
  await page.locator('#forge-ballot').click();
  await expect(page.locator('#attack-result')).toContainText('rigged');

  // Walk the decryption identity so the stepper list renders.
  for (let step = 1; step <= 4; step += 1) {
    await page.locator('#step-decrypt').click();
    await expect(page.locator('#stepper-list li')).toHaveCount(step);
  }

  // Factor the 64-bit modulus so the recovered-key report is scanned too.
  await page.locator('#factor-key').click();
  await expect(page.locator('#factor-result')).toContainText('Factored.', { timeout: 60_000 });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await driveDemo(page);
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await driveDemo(page);
  await prepare(page);
  await scan(page);
});
