# TrustCheck Design System (`DESIGN.md`)

## 1. Philosophy: Security Research Instrument
TrustCheck is designed as a calibrated **security research instrument** rather than a consumer antivirus dashboard or generic SaaS marketing site.
- **Evidence is the interface**: Every risk claim is anchored to the exact substring matched in the user's pasted input (`URL`, `Text`, `UPI`).
- **Restraint is the aesthetic**: High-contrast typographic hierarchy, crisp 1px hairline borders, flat surfaces, and tabular numerical readouts.
- **Strict Anti-Bloat Bans**:
  - Zero gradients, glassmorphism (`backdrop-blur`), neon glows, or heavy drop shadows.
  - Zero stock illustrations, 3D graphics, shield/lock clip-art, or decorative status dots.
  - Zero emoji-heavy UI or alarmist fear-mongering copy.

---

## 2. Color & Surface Tokens

All tokens are exposed as CSS custom properties in `/src/index.css` and mapped into Tailwind v4 `@theme` utilities.

| Token | CSS Variable | Hex / Value | Usage |
| :--- | :--- | :--- | :--- |
| **Ground Surface** | `--color-ground` | `#0b0b0e` | Primary page canvas and dark inspection bays |
| **Card Surface** | `--color-card` | `#ffffff` | High-contrast evidence & report cards on dark ground |
| **Dark Border** | `--color-border-dark` | `rgba(255, 255, 255, 0.10)` | 1px hairline dividers on `#0b0b0e` ground |
| **Light Border** | `--color-border-light` | `#e6e6ea` | 1px hairline dividers inside `#ffffff` cards |
| **Ink (On Dark)** | `--color-ink-dark` | `#f4f4f6` | Primary text on `#0b0b0e` ground |
| **Ink (On White)** | `--color-ink-light` | `#0b0b0e` | Primary text inside `#ffffff` cards |
| **Muted Text** | `--color-muted` | `#8a8a93` | Secondary labels, captions, and metadata |
| **Primary Accent** | `--color-accent` | `#ff4a1f` | Strictly reserved for the 100-dot risk meter fill, primary Analyze button, and key evidence emphasis |
| **Verdict: Safe** | `--color-verdict-safe` | `#1f9d6b` | Used only on the Verdict Banner and Meter Label (`< 30`) |
| **Verdict: Suspicious** | `--color-verdict-suspicious` | `#d98a00` | Used only on the Verdict Banner and Meter Label (`30–64`) |
| **Verdict: Scam** | `--color-verdict-scam` | `#d92d20` | Used only on the Verdict Banner and Meter Label (`>= 65`) |

### Accessibility & Non-Hue-Only Signaling
- **WCAG AA Contrast**: `#f4f4f6` on `#0b0b0e` (`17.8:1`), `#0b0b0e` on `#ffffff` (`19.4:1`), and `#8a8a93` on `#0b0b0e` (`5.6:1`) / `#ffffff` (paired with darker `#52525b` for small body copy on white to maintain `>= 4.5:1`).
- **Never Rely on Colour Alone**: Verdict states (`safe`, `suspicious`, `scam`) are always paired with an explicit semantic icon (`CheckCircle2`, `AlertTriangle`, `OctagonAlert`), a bold uppercase verdict label, and the numerical score (`0–100`).

---

## 3. Typography & Strict Scale

- **Display & Score Numerals**: `'Bricolage Grotesque', sans-serif` (`--font-display`)
- **UI & Prose**: `'Inter', sans-serif` (`--font-sans`)
- **Evidence Spans & Identifiers**: `'JetBrains Mono', monospace` (`--font-mono`)
- **Tabular Discipline**: All scores, weights, and counters enforce `font-variant-numeric: tabular-nums`.

### Type Scale (`px`)
| Step | Token | Size | Line Height | Typical Role |
| :--- | :--- | :--- | :--- | :--- |
| **xs** | `--text-12` | `12px` (`0.75rem`) | `1.4` | Category labels, character counter, rule IDs, microcopy |
| **sm** | `--text-14` | `14px` (`0.875rem`) | `1.5` | Example buttons, secondary descriptions, action items |
| **base** | `--text-16` | `16px` (`1rem`) | `1.6` | Textarea input, plain-language explanation, highlighted evidence |
| **lg** | `--text-20` | `20px` (`1.25rem`) | `1.35` | Card headings, scam type classification |
| **xl** | `--text-32` | `32px` (`2rem`) | `1.15` | Verdict banner headline, mobile hero display |
| **2xl** | `--text-56` | `56px` (`3.5rem`) | `1.04` | Hero headline (`"See through the scam."`) and score readout |

---

## 4. Geometry, Layout & Components

- **Border Radius**: Maximum `8px` (`--radius-max: 8px`) for outer cards and containers; `6px` or `4px` for nested controls and inline evidence highlights.
- **Elevation**: Zero heavy drop shadows. Boundaries are defined strictly by surface contrast (`#ffffff` card on `#0b0b0e` ground) and `1px` hairline borders.
- **10x10 Dot-Matrix Risk Meter**:
  - A `10 × 10` CSS Grid of exactly `100` circular cells (`index 0..99`).
  - Dots `< score` are filled in `--color-accent` (`#ff4a1f`).
  - Unfilled dots (`>= score`) render at `12%` opacity (`rgba(11, 11, 14, 0.12)` on light card or `rgba(244, 244, 246, 0.12)` on dark surface).
  - Dots animate sequentially via staggered transition delays (`2ms` per dot, settling within the `150–250ms` window). When `prefers-reduced-motion: reduce` is active, transitions are instantaneous (`0ms`).

---

## 5. Motion & Voice

- **Motion Budget**: `150ms–250ms` `cubic-bezier(0.16, 1, 0.3, 1)` (`ease-out`) on `opacity` and `transform` only. No decorative looping animations.
- **Voice & Tone**: Calm, empirical, plain, and direct. Small Hinglish touches (`"Nazar rakho."`, `"Ruko. Socho. Phir click karo."`) ground the instrument in everyday Indian digital life without sacrificing clarity.
