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
      opacity: 1 !important;
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

  await page.locator('#decrypt-form button[type="submit"]').click();
  await expect(page.locator('#decrypt-result')).toContainText('Decrypted value');

  await page.locator('#sum-form button[type="submit"]').click();
  await expect(page.locator('#sum-result')).toContainText('Plaintext sum');

  await page.locator('#aggregation-form button[type="submit"]').click();
  await expect(page.locator('#aggregation-result')).toContainText('aggregate total');

  await page.locator('#election-form button[type="submit"]').click();
  await expect(page.locator('#election-result')).toContainText('Decrypted tally');
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
