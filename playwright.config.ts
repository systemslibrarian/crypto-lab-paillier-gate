import { defineConfig } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build before serving: preview serves dist/, so without this a run can test a
    // stale bundle, and a FAILED build leaves the last good bundle in place and
    // passes green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4264 --strictPort',
    url: 'http://localhost:4264/crypto-lab-paillier-gate/',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4264/crypto-lab-paillier-gate/',
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
