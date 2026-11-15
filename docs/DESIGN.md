# Design

The theme tokens live in exactly one file: `dashboard/theme.css` (and only there).
The agent UI loads the same file, so there is one source of truth.

## Tokens

```
--bg: #061a1c            page background (deep teal-black)
--panel: #0b2a2e         cards, tables
--panel-2: #0f3a3f       hover / selected rows
--border: #17484e
--text: #e6f4f1
--muted: #8fb5b2
--accent: #14b8a6        primary teal: buttons, active nav, links
--accent-bright: #2dd4bf focus ring, chart highlight
--ok: #4ade80            granted (yellower green than the teal accent)
--bad: #f87171           denied
--warn: #fbbf24          advisory only
```

Fonts: system UI sans for text; Consolas / "Cascadia Mono" for ids, hashes and
timestamps. Base 15px, line-height 1.5, 8px spacing grid, 6px radius.

## Contrast (measured, not estimated)

WCAG 2.x relative luminance, `(L1+0.05)/(L2+0.05)`:

| Pair | Ratio | Text needs 4.5:1 |
|---|---|---|
| `--text` on `--bg` | **15.85:1** | PASS |
| `--text` on `--panel` | **13.41:1** | PASS |
| `--muted` on `--panel` | **6.80:1** | PASS |
| `--muted` on `--bg` | **8.04:1** | PASS |
| `--accent` on `--bg` (links) | **7.20:1** | PASS |
| `--accent` on `--panel` | **6.09:1** | PASS |
| `--accent-bright` on `--bg` (focus ring) | **9.62:1** | PASS (needs 3:1 for UI) |
| `--ok` on `--panel` | **8.70:1** | PASS |
| `--bad` on `--panel` | **5.48:1** | PASS |
| `--warn` on `--panel` | **9.08:1** | PASS |
| Button text `#04211f` on `--accent` | **6.79:1** | PASS |
| `--panel` vs `--bg` (surfaces, not text) | 1.18:1 | intentionally subtle |

Every text pair used in the UI clears 4.5:1. The panel/background separation is
deliberately low — separation is carried by the 1px `--border`, not by a
brightness jump.

## Rules followed

- Flat surfaces, thin borders. No gradients, glows, neon or shadows.
- One animation only: a 150ms colour fade on hover
  (`transition: background-color 150ms, border-color 150ms, color 150ms`).
  The loading skeleton pulses opacity, which is a loading state, not decoration.
- **Status is never colour alone.** Every status is a glyph plus words:
  `✔ GRANTED`, `✖ DENIED`, `⚠ Known`, `✔ enrolled`, `✖ not enrolled`,
  `✔ Chain intact`, `✖ Broken at record N`.
- **Privacy is the visual story.** The Overview carries a permanent
  *Posture values stored: 0* card and a *What the server never saw* panel; the
  decision detail splits "what the server saw" from "what stayed on the laptop",
  with `never leaves the device` tags.
- Admin answers "are we safe?" in one screen: compliance %, granted/denied
  today, devices, policy version, and the denial-reason chart.

## Screens

| Screen | Contents |
|---|---|
| Login | single card, password field, plain error, no hints |
| Overview | 6 cards, denial-reason bars, recent decisions, privacy panel |
| Decisions | filters (result, reason, from, to), table, pagination, detail panel |
| Policy | current vs new, change preview, confirm dialog, version bump note |
| Devices | device table, enrollment-code generator (single use, expiring) |
| Log Integrity | big intact/broken status, verify button, latest hash + copy |
| Advisory | KEV table, "advisory only" banner, Review policy button |
| Gate denied (port 8081) | self-contained 401 page: no token, expired token, or app unreachable |

## States

- **Loading:** skeleton rows/cards (`.skeleton`), no spinners.
- **Empty:** one helpful sentence, e.g. "No attestations yet. Run
  `node agent attest` on a laptop."
- **Error:** red banner with the message and a Retry button.
- **Success:** toast, `aria-live="polite"`, disappears after 4 s.

## Accessibility and responsive

- Semantic elements: `table`, `th scope`, `button`, `label for`, `dialog`.
- Keyboard reachable; visible 2px `--accent-bright` focus ring on every control.
- `aria-live` on the toast; `role="alert"` on the login error.
- Collapses at 900px: the 220px sidebar becomes a horizontal top nav.
- Verified layout at 1280px and at 390px in the CSS breakpoints (390px: two
  columns of cards, 1fr chart). Visual check on a real device is on the manual
  checklist.

## Microcopy

| Code | Text |
|---|---|
| `POLICY_MISMATCH` | Device used an outdated policy |
| `REPLAY` | This proof was already used |
| `EXPIRED` | Challenge expired, please retry |
| `PROOF_INVALID` | Proof could not be verified |
| `BAD_SIGNATURE` | Device identity could not be verified |
| `NON_COMPLIANT` | Device does not meet policy |
| `BAD_REQUEST` | Request was malformed |
| `CHALLENGE_DEVICE_MISMATCH` | Challenge was issued to a different device |
| `RATE_LIMITED` | Too many attempts, please wait |

The text never says which value failed. "Device does not meet policy" is all a
denied laptop learns.
