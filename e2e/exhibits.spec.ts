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

/**
 * REGRESSION — two panels ignored their own `hidden` attribute.
 *
 * The UA rule is `[hidden] { display: none }`, an attribute selector that any
 * class rule setting `display` outranks. `.ledger { display: grid }` and
 * `.handoff { display: flex }` did, so from FIRST PAINT — before any keypair
 * existed — the page rendered a 542x361 homomorphic-addition ledger reading
 * "Enc(A) x mod N² Enc(B) = product ciphertext decrypt →" with every value slot
 * empty, and a 542x84 "Send this ciphertext to Step 3 →" hand-off for a
 * ciphertext that did not exist. Four other panels with the same attribute were
 * fine, which is why it went unnoticed.
 *
 * Asserted as the invariant over the attribute rather than over two ids: an
 * element carrying `hidden` must paint nothing, whichever element it is.
 */
test('every element marked hidden actually renders nothing', async ({ page }) => {
  await open(page);
  const rendered = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))
      .map((el) => {
        const r = el.getBoundingClientRect();
        return {
          id: el.id || el.className,
          display: getComputedStyle(el).display,
          box: `${Math.round(r.width)}x${Math.round(r.height)}`,
        };
      })
      .filter((x) => x.display !== 'none'),
  );
  expect(rendered, 'elements with [hidden] that still paint').toEqual([]);

  // And the two that were broken are genuinely among the hidden set, so this
  // does not pass by their having stopped carrying the attribute.
  for (const id of ['#sum-ledger', '#encrypt-handoff']) {
    await expect(page.locator(id)).toHaveAttribute('hidden', '');
    await expect(page.locator(id)).toBeHidden();
  }
});

/**
 * REGRESSION — an enabled control whose click did nothing.
 *
 * `#add-to-ledger` was enabled by the blanket "everything unlocks with a key"
 * rule, but its handler returns early when nothing has been encrypted yet. With
 * the hand-off panel wrongly visible (above), a reader with a fresh key could
 * press "Send this ciphertext to Step 3 →" and get no ciphertext, no slot, and
 * no message — the control reported no outcome at all.
 */
test('the Step 3 hand-off is only offered once there is a ciphertext to hand off', async ({
  page,
}) => {
  await open(page);
  await generateKey(page, '64');

  // A key, but nothing encrypted: the control must not claim to be operable.
  await expect(page.locator('#add-to-ledger')).toBeDisabled();
  await expect(page.locator('#encrypt-handoff')).toBeHidden();

  await page.locator('#plaintext-input').fill('42');
  await page.locator('#encrypt-form button[type="submit"]').click();
  await expect(page.locator('#encrypt-handoff')).toBeVisible();
  await expect(page.locator('#add-to-ledger')).toBeEnabled();

  // And now it does something observable.
  await page.locator('#add-to-ledger').click();
  await expect(page.locator('#handoff-note')).toContainText('Sent Enc(42) to slot A');
  await expect(page.locator('#sum-a')).toHaveValue('42');
  await expect(page.locator('#sum-source-note')).toContainText('you');
});

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

/**
 * REGRESSION — "Decrypted value: N" outlived the ciphertext that produced it.
 *
 * The verdict does not echo its input, so it reads as a statement about the box
 * directly above it. Pasting a different ciphertext left it standing — while
 * the stepper immediately below, which IS keyed on the ciphertext, correctly
 * started a fresh trace. Two adjacent panels then described two different
 * ciphertexts at the same moment.
 */
test('the decrypt verdict is retired when the ciphertext under it changes', async ({ page }) => {
  await open(page);
  await generateKey(page, '64');

  await page.locator('#plaintext-input').fill('111');
  await page.locator('#encrypt-form button[type="submit"]').click();
  await page.locator('#decrypt-form button[type="submit"]').click();
  await expect(page.locator('#decrypt-result')).toContainText('Decrypted value: 111');

  // A different ciphertext for a different plaintext, typed into the box.
  await page.locator('#plaintext-input').fill('222');
  await page.locator('#encrypt-form button[type="submit"]').click();
  const second = await page.locator('#ciphertext-output').inputValue();
  await page.locator('#decrypt-input').fill('1');
  await expect(page.locator('#decrypt-result')).not.toContainText('Decrypted value: 111');
  await page.locator('#decrypt-input').fill(second);
  await expect(page.locator('#decrypt-result')).not.toContainText('Decrypted value:');

  await page.locator('#decrypt-form button[type="submit"]').click();
  await expect(page.locator('#decrypt-result')).toContainText('Decrypted value: 222');
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
    // REGRESSION: this test picked the one case that falsifies the sentence the
    // panel used to print — "It is below the honest 6" — and then asserted the
    // very number that disproves it. See the invariant test below.
    await expect(result).not.toContainText('below the honest');
  });

  /**
   * REGRESSION — "It is below the honest N", printed unconditionally.
   *
   * With Encrypt-then-MAC on, the rejected ballot is dropped, so the new tally
   * is the honest one minus that voter's own vote. Votes here are 0 or 1: drop
   * a 0 and the tally does not move. The sentence asserted a strict inequality
   * one clause after printing the two numbers that contradict it — false for
   * 4 of the 10 targets selectable in the shipped ballot list (Voters 3, 5, 7
   * and 10, the four zeros in "1, 1, 0, 1, 0, 1, 0, 1, 1, 0").
   *
   * Both suites had encoded the blind spot: this file and tests/ballots.test.ts
   * each deliberately chose index 2 *because* dropping it costs the tally
   * nothing, and each asserted the unchanged tally — while never reading the
   * sentence printed beside it.
   *
   * The assertion is the invariant between two rendered numbers, not a string:
   * whichever comparison the panel states must be the comparison that holds
   * between the tally it prints and the honest tally it names.
   */
  test('the authenticated verdict states the comparison that actually holds, for every target', async ({
    page,
  }) => {
    test.setTimeout(120_000);
    await open(page);
    await generateKey(page, '64');

    await page.locator('#election-form button[type="submit"]').click();
    await expect(page.locator('#election-result')).toContainText('Honest tally decrypts to 6 / 10');
    await page.locator('#attack-authenticate').check();
    await page.locator('#attack-boost').fill('100');

    const votes = [1, 1, 0, 1, 0, 1, 0, 1, 1, 0];
    const result = page.locator('#attack-result');
    let sawEqual = 0;
    let sawBelow = 0;

    for (const [index, vote] of votes.entries()) {
      // A fresh seal per target, so each one is measured against the honest
      // ballot box rather than against the accumulated damage of the last.
      await page.locator('#election-form button[type="submit"]').click();
      await expect(page.locator('#election-result')).toContainText('Honest tally decrypts to 6 / 10');
      await page.locator('#attack-target').selectOption(String(index));
      await page.locator('#forge-ballot').click();
      await expect(result).toContainText('Encrypt-then-MAC caught it.', { timeout: 30_000 });

      const text = ((await result.textContent()) ?? '').replace(/\s+/g, ' ');
      const newTally = Number(/decrypts to (\d+)/.exec(text)?.[1]);
      const honest = Number(/honest (\d+)/.exec(text)?.[1]);
      expect(honest, `Voter ${index + 1}: panel must name the honest tally`).toBe(6);
      expect(newTally, `Voter ${index + 1}: dropping a ${vote} vote`).toBe(6 - vote);

      if (newTally === honest) {
        sawEqual += 1;
        expect(text, `Voter ${index + 1} voted 0: tally unchanged`).toContain(
          `exactly the honest ${honest}`,
        );
        expect(text).not.toContain('below the honest');
      } else {
        sawBelow += 1;
        expect(text, `Voter ${index + 1} voted 1: tally dropped`).toContain(
          `${honest - newTally} below the honest ${honest}`,
        );
        expect(text).not.toContain('exactly the honest');
      }
      // Either way the forgery itself failed, which is the exhibit's point.
      expect(text).toContain('never landed');
    }

    // Both branches are real and both were driven — the old copy was wrong in
    // exactly the four the old tests aimed at.
    expect(sawEqual).toBe(4);
    expect(sawBelow).toBe(6);
  });

  /**
   * REGRESSION — the verdict outlived the controls it describes.
   *
   * The panel's own copy says "Turn on the tag check above and run the same
   * attack again", so toggling is an expected move; between the toggle and the
   * next press the box still read "The tally is rigged … The ballot box
   * accepted all 10 ballots because it checked nothing" with the verify-tags
   * checkbox visibly ticked. Same for retargeting: the verdict named a voter
   * that was no longer the selected one.
   */
  test('changing the attack controls retires the verdict they no longer describe', async ({
    page,
  }) => {
    await open(page);
    await generateKey(page, '64');
    await page.locator('#election-form button[type="submit"]').click();
    await expect(page.locator('#ballot-attack')).toBeVisible();

    const result = page.locator('#attack-result');
    await page.locator('#attack-target').selectOption('0');
    await page.locator('#forge-ballot').click();
    await expect(result).toContainText('The tally is rigged.');

    // Ticking the box must not leave "it checked nothing" on screen.
    await page.locator('#attack-authenticate').check();
    await expect(result).not.toContainText('checked nothing');
    await expect(result).not.toContainText('The tally is rigged.');
    await expect(result).toHaveText('Nothing forged yet.');

    await page.locator('#forge-ballot').click();
    await expect(result).toContainText('Encrypt-then-MAC caught it.');

    // Retargeting invalidates a verdict that names a voter.
    await page.locator('#attack-target').selectOption('3');
    await expect(result).toHaveText('Nothing forged yet.');

    await page.locator('#forge-ballot').click();
    await expect(result).toContainText('Encrypt-then-MAC caught it.');

    // So does changing the amount the verdict quotes.
    await page.locator('#attack-boost').fill('7');
    await expect(result).toHaveText('Nothing forged yet.');
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

/**
 * REGRESSION — the one panel a fresh keypair did not retire.
 *
 * Generating a key returns five result boxes to placeholders and hides the
 * semantic stack, the sum ledger and the ballot box. The aggregation breakdown
 * was left standing: its "Enc(x)^w mod N² (truncated)" column kept showing
 * ciphertexts computed under the PREVIOUS modulus, under a caption reading
 * "Per-row contribution to the weighted total", directly beside a result box
 * saying "Run a hospital-style aggregation or weighted total with the new
 * keypair". Regenerate at a different bit length and the ciphertexts on screen
 * were not even the right length for the key in the metrics panel above.
 *
 * Driven as a transition — run, then regenerate — which is the only way a
 * written-but-never-cleared panel is visible at all.
 */
test('a fresh keypair retires the aggregation breakdown with everything else', async ({ page }) => {
  test.setTimeout(120_000);
  await open(page);
  await generateKey(page, '64');

  await page.locator('#aggregation-form button[type="submit"]').click();
  await expect(page.locator('#aggregation-rows tr')).toHaveCount(5);
  const before = await page.locator('#aggregation-rows tr td:last-child').allTextContents();
  expect(before.every((t) => t.length > 0)).toBe(true);

  // A different key size, so a surviving row would be showing arithmetic that
  // is impossible under the modulus now on screen.
  await generateKey(page, '160');

  // The invariant, stated over the panels rather than the copy: nothing may be
  // asserting a result while its own result box says nothing has been run.
  await expect(page.locator('#aggregation-result')).toContainText('with the new keypair');
  await expect(page.locator('#aggregation-table')).toBeHidden();
  await expect(page.locator('#aggregation-rows tr')).toHaveCount(0);

  // And the same reset must leave the other derived panels retired too, so the
  // fix is a rule about fresh keys rather than a patch for one table.
  await expect(page.locator('#semantic-demo')).toBeHidden();
  await expect(page.locator('#sum-ledger')).toBeHidden();
  await expect(page.locator('#ballot-attack')).toBeHidden();
  await expect(page.locator('#stepper-list li')).toHaveCount(0);

  // Re-running under the new key repopulates it.
  await page.locator('#aggregation-form button[type="submit"]').click();
  await expect(page.locator('#aggregation-rows tr')).toHaveCount(5);
});

/**
 * REGRESSION — "≈ N steps for a K-bit prime" named a prime size the key did not
 * have. N = p·q with p and q of exactly half the requested width, so the
 * modulus lands on the requested width or one bit under it (87 of 200 keygens
 * across the five shipped sizes). K was floor(modulusBits / 2), which is one
 * short in the latter case, and the estimate beside it was computed from the
 * modulus — so the sentence's two halves disagreed with each other.
 *
 * Asserted as the invariant: the step count the panel prints must be
 * 1.18·sqrt(2^K) for the very K it prints, whichever way the modulus fell.
 */
test('the give-up estimate agrees with the prime size it names', async ({ page }) => {
  test.setTimeout(240_000);
  await open(page);

  // Drive to the state the defect needs rather than hoping for it: keep
  // generating until N comes out ONE BIT SHORT of the selected 160. That is the
  // case where floor(modulusBits / 2) named 79 for two 80-bit primes, and it
  // happened in 25 of 40 keygens at this size — but "usually" is not a test.
  let modulusBits = 0;
  for (let attempt = 0; attempt < 25 && modulusBits !== 159; attempt += 1) {
    await generateKey(page, '160');
    modulusBits = Number(await page.locator('#metric-bits').textContent());
  }
  expect(modulusBits, 'never drew a short modulus in 25 keygens').toBe(159);

  await page.locator('#factor-key').click();
  const result = page.locator('#factor-result');
  await expect(result).toContainText('Gave up.', { timeout: 120_000 });

  const text = ((await result.textContent()) ?? '').replace(/\s+/g, ' ');
  const steps = Number(/≈ ([\d,]+) steps/.exec(text)?.[1].replace(/,/g, ''));
  const primeBits = Number(/for a (\d+)-bit prime/.exec(text)?.[1]);

  // The primes are half the SELECTED length, never half a short modulus.
  expect(primeBits).toBe(80);
  expect(steps).toBe(Math.round(1.18 * Math.sqrt(2 ** primeBits)));
  // And it is not silently reading the modulus instead.
  expect(primeBits).not.toBe(Math.floor(159 / 2));
});
