# Relay brand assets

Relay's mark is a type-only wordmark, `relay_`: the product name in lowercase monospace
followed by a teal terminal cursor. There is deliberately no mascot or emblem: Relay is
infrastructure you drive from a terminal, and a separate product from Gleipnir, which has the
wolf-and-chain badge. The two share a palette, not a crest.

| File | Use |
|---|---|
| `relay-wordmark-light.svg` | On light backgrounds: near-black `relay`, teal `#0a8276` cursor |
| `relay-wordmark-dark.svg` | On dark backgrounds: cream `#ece6da` `relay`, teal `#4fb3a8` cursor |
| `relay-icon.svg` | Square spaces (favicon, avatar, app icon): cream `r_` on a teal `#0a8276` rounded square; works on either background |

The SVGs are the only committed form. Where a PNG is needed, export one from the SVG at the
size it needs rather than committing it: a committed raster is a second copy nothing keeps in
step.

## Rules

- **One accent.** Teal appears only on the cursor (or as the icon's ground). The letters are
  near-black `#1a1a1a` on light and cream `#ece6da` on dark.
- **Teal is also the Console's interactive accent** (owner decision, 2026-10-01): links,
  primary buttons, focus rings and the live indicator use `#0a8276` on light and `#4fb3a8` on
  dark, as the `--color-accent` token in `console.css`. Where the teal carries small text on a
  light ground, the Console uses a darker step to clear WCAG AA. It means "you can act here"
  and is never one of the Console's semantic colours.
- **Don't re-set it in a live font.** The SVGs are the letterforms as outlines, so they render
  identically everywhere. If the mark changes, regenerate the outlines rather than editing the
  paths by hand.
- **Leave clear space.** Keep at least the cursor's width clear around the wordmark.

## Typeface

The letterforms are JetBrains Mono ExtraBold, converted to outlines. JetBrains Mono is
licensed under the SIL Open Font License 1.1; the licence travels with these files as
`FONT-LICENSE-JetBrainsMono.txt`.

## Where it is used

- `README.md`: the header, switching wordmark on the reader's colour scheme.
- The Console: the sidebar, sign-in brand and favicon. The Console serves its own copies of
  the three SVGs, because its content security policy admits images only from its own origin;
  a test keeps those copies byte-identical to the ones here.
