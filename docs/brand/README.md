# Relay brand assets

Relay's mark is a type-only wordmark, `relay_`: the product name in lowercase monospace
followed by a teal terminal cursor. There is deliberately no mascot or emblem. Relay is
infrastructure you drive from a terminal, and it is a separate product from Gleipnir, which
has the wolf-and-chain badge. Relay and Gleipnir share a palette, not a crest, though
Relay's teal is also the Console's interactive accent (see Rules).

| File | Use |
|---|---|
| `relay-wordmark-light.svg` | On light backgrounds: near-black `relay`, teal `#0a8276` cursor |
| `relay-wordmark-dark.svg` | On dark backgrounds: cream `#ece6da` `relay`, teal `#4fb3a8` cursor |
| `relay-icon.svg` | Square spaces (favicon, avatar, app icon): cream `r_` on a teal `#0a8276` rounded square; works on either background |

The SVGs are the only committed form. Where a PNG is needed (an avatar upload, a slide,
a tool that will not take SVG), export one from the SVG at the size it needs rather than
committing it: a committed raster is a second copy that nothing keeps in step.

## Rules

- **One accent.** Teal appears only on the cursor (or as the icon's ground). The letters are
  near-black `#1a1a1a` on light and cream `#ece6da` on dark.
- **Teal is a brand colour, and the Console's interactive accent.** Amended by owner decision
  on 2026-10-01: the Console's interactive colour (links, primary buttons, focus rings, the
  live indicator) is this teal, `#0a8276` on light and `#4fb3a8` on dark, as the
  `--color-accent` token in `console.css`. Where the teal has to carry small text on a light
  ground, the Console uses a darker step of it to clear WCAG AA. The teal still means "you can
  act here" and is never one of the Console's semantic colours. The mark itself is unchanged.
- **Don't re-set it in a live font.** The SVGs are the letterforms as outlines, so they
  render identically everywhere and need no font. If the mark ever changes, regenerate the
  outlines rather than editing the paths by hand.
- **Leave clear space.** Keep at least the cursor's width clear around the wordmark.

## Typeface

The letterforms are JetBrains Mono ExtraBold, converted to outlines. JetBrains Mono is
licensed under the SIL Open Font License 1.1; the licence travels with these files as
`FONT-LICENSE-JetBrainsMono.txt`.

## Where it is used

- `README.md`: the header, switching between the light and dark wordmark on the reader's
  colour scheme.
- The Console: the sidebar and sign-in brand, and the favicon. The Console serves its own
  copies of the three SVGs from its embedded assets, because the content security policy
  admits images only from its own origin; a test keeps those copies byte-identical to the
  ones here.
