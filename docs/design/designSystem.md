# Design system

**Code:** [`client/src/styles/tokens.css`](../../client/src/styles/tokens.css), [`client/src/styles/app.css`](../../client/src/styles/app.css), [`client/src/components/common.jsx`](../../client/src/components/common.jsx)

## Personality

A password manager holds something personal: someone's digital identity. Tessera's interface aims to feel **trustworthy, precise, discreet and in control**. It is a carefully made tool, not a showy dashboard.

What we deliberately avoided: oversized headings, gradients, floating cards everywhere, decorative illustrations, generic statistics tiles, pill-shaped everything, and colour used as decoration.

**Direction:** a warm stone foundation with dark ink text, one intentional accent (pine green), hairline borders instead of shadows, compact information density, and precise typography. It has a charcoal dark theme that follows the operating system.

## The name and mark

A *tessera* is one small tile of a Roman mosaic. Roman soldiers also received the night's **watchword** on a tablet called a tessera, so it is a fitting name for a password manager. The mark is four tiles, one in the accent colour.

## Tokens

### Colour

Every colour has **one meaning**:

| Token | Light | Dark | Meaning |
|---|---|---|---|
| `--accent` | `#2c5a49` | `#82b9a1` | Primary action, current selection, focus |
| `--danger` | `#a3392d` | `#e07b6d` | Something is wrong, or the action is destructive |
| `--warning` | `#8a5a0f` | `#d8a64d` | Needs attention (e.g. wrong password, conflict) |
| `--success` | `#2c6a4a` | `#82b9a1` | A meaningful success or security state |
| `--surfaceApp/Panel/Raised` | stone → white | charcoal steps | Layering by tone, not shadow |
| `--textPrimary/Secondary/Tertiary` | ink → grey | light → grey | Hierarchy |

The accent and success share a hue on purpose: in a security tool, "selected/primary" and "secure/OK" are consonant. Red is reserved for danger, so a rollback warning really stands out.

### Typography

| Use | Font |
|---|---|
| Interface | **IBM Plex Sans**: distinctive, highly legible, slightly technical |
| Passwords, generated values, counts, parameters | **IBM Plex Mono**: unambiguous glyphs (`0` vs `O`, `l` vs `1`), ligatures off |

Sizes are compact (11–22 px, 14 px base). Headings are weighted, not huge.

### Shape and spacing

- One radius, **4 px**, everywhere (3 px for tiny keycaps).
- **1 px hairlines** (`--borderSubtle`) separate rows and regions. There are no drop shadows.
- A 4 px spacing scale (`--space1` … `--space10`).

### Motion

Short (120–180 ms) and only for meaningful feedback: hover, the copy confirmation fading in, the spinner during key derivation. `prefers-reduced-motion` turns animation off.

### Icons

One family: **Lucide**, at 15 px, stroke icons only, always paired with a label or an `aria-label`.

## Layout

```
┌──────────┬──────────────────────┬────────────────────────────────────┐
│ Sidebar  │ Search  [/]          │ [G] github.com            Edit  🗑  │
│          │ 4 items  Name ▾  +New│     ada.lovelace                   │
│ All items│──────────────────────│────────────────────────────────────│
│ Generator│ [G] github.com    1m │ Username   ada.lovelace         ⧉  │
│ Settings │     ada.lovelace     │ Password   ••••••••••••      👁 ⧉  │
│          │ [M] mail.example…    │ Website    github.com           ↗  │
│          │                      │ Notes      Work account…        ⧉  │
│ email    │                      │                                    │
│ Lock  ⇥  │                      │ Updated … · Created …              │
└──────────┴──────────────────────┴────────────────────────────────────┘
```

- **Sidebar:** sections, the account, a security status line ("Encrypted · version 12 · locks after 5 min") and a prominent **Lock**.
- **List:** fast, prominent search (press `/`), sort by name or recently updated, and rows showing monogram, site, username and last update.
- **Detail panel:** opens beside the list without navigating away. Fields are **aligned rows separated by hairlines**, not separate cards.
- Under 900 px the layout collapses to one column (list → detail with a back button).

## Details that give it character

| Detail | Behaviour |
|---|---|
| **Copy** | Icon becomes a check, and a small inline note says "Copied · clears in 30s" |
| **Reveal** | Deliberate click; shows a countdown ("Hides in 20s"); re-masks itself |
| **Mask** | Always 12 dots, so the true length isn't hinted |
| **Empty vault** | Product-specific: explains that items are encrypted in the browser, with one clear action |
| **No search results** | Says what search covers (website, username, notes) and offers "Clear search" |
| **Nothing selected** | Useful tips (`/` to search, reveal, clipboard clearing) |
| **Lock screen** | Unmistakable: a "LOCKED" label, the account's email, a single password field, and a way out ("Not you? Sign out") |
| **Unlock progress** | Names the real steps: "Deriving keys (PBKDF2-SHA256)…", "Verifying with server…", "Checking vault integrity…" |
| **Security errors** | Rollback and tampering get a red, titled explanation in plain language, not a generic error |
| **Generator strength** | A label, an entropy figure *and a sentence explaining why* |
| **Delete** | Inline confirmation bar naming the item, not a modal |
| **Sign-up** | States plainly that there is no password reset, and why |

## Accessibility

- Every icon-only button has an `aria-label` and `title`.
- Visible focus ring (`--focusRing`) on all interactive elements via `:focus-visible`.
- Status messages use `role="status"`, and security errors use `role="alert"`.
- Colour is never the only signal: messages pair colour with an icon and text.
