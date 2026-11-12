# Password generator

**Code:** [`packages/crypto/src/passwordGenerator.js`](../../packages/crypto/src/passwordGenerator.js), UI in [`GeneratorView.jsx`](../../client/src/components/GeneratorView.jsx) and the "Generate" button in [`EntryForm.jsx`](../../client/src/components/EntryForm.jsx)

## A cryptographically secure source

All randomness comes from `crypto.getRandomValues`, the browser's interface to the operating system's **cryptographically secure pseudorandom number generator (CSPRNG)**. `Math.random()` is never used: it is designed for speed, not unpredictability, and its output can be reconstructed from a few observed values.

## Modulo bias

The obvious way to pick a character is:

```js
pool[randomByte % pool.length]   // ❌ biased
```

Take a 62-character pool (`a–z A–Z 0–9`). A random byte has 256 equally likely values, and 256 = 4 × 62 + 8. The values 0–247 map evenly (4 each), but the leftover 248–255 map onto the **first 8 characters** again. Those 8 characters come up 5/256 of the time instead of 4/256, which is **25% more often**. Generated passwords become measurably easier to guess.

## Rejection sampling

`randomIndex(n)` removes the bias:

1. Draw a 32-bit random value `v` (0 … 2³² − 1).
2. Let `limit = 2³² − (2³² mod n)`, the largest multiple of n that fits.
3. If `v ≥ limit`, **throw it away** and draw again.
4. Otherwise return `v mod n`.

Every accepted value falls in a range that divides evenly into n buckets, so every index is exactly equally likely. For our pool sizes, a redraw happens less than once in 2²⁴ draws, so it costs nothing in practice.

A unit test runs a rough chi-squared check on 20,000 draws.

## Required character classes

Many sites demand "at least one digit and one symbol". If a generated password is missing an enabled class, the **whole password is discarded and regenerated**. That's rejection sampling again, at the password level, and it keeps the result uniform over all passwords that satisfy the rule. The tempting shortcut of overwriting a random position with a digit would make some positions predictable.

## Options

| Option | Default |
|---|---|
| Length | 20 (8–128) |
| Lowercase, uppercase, digits, symbols | all on; at least one must stay on |
| Avoid look-alikes (`I l 1 O 0 o`) | off |

Settings are remembered per device (localStorage; they are not secret) and also used by the **Generate** button in the item form.

## Entropy and the strength explanation

For a random password, the honest strength measure is **entropy**: the number of equally likely possibilities, in bits.

```
entropy = length × log2(pool size)
```

20 characters from all four classes (88 symbols): 20 × log2(88) ≈ **129 bits**.

The UI explains the number in words instead of showing only a coloured bar:

| Bits | Label | Explanation shown |
|---|---|---|
| < 45 | Weak | Could be cracked quickly from a leaked hash |
| 45–64 | Fair | Resists casual attacks but not a determined offline attacker |
| 65–89 | Strong | Out of reach for offline guessing with current hardware |
| ≥ 90 | Excellent | Far beyond any feasible guessing attack |

For a sense of scale: at 10¹² guesses per second (≈ 2⁴⁰), 2⁴⁰ guesses take about a second, while 2⁸⁰ would take tens of millions of years.

This estimate applies only to *generated* passwords. Entropy formulas say little about human-chosen passwords, whose structure attackers exploit, so the app does not score those.
