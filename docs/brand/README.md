# Relay brand assets

Relay's mark is a type-only wordmark, `relay_`: the product name in lowercase monospace
followed by a teal terminal cursor. There is deliberately no mascot or emblem. Relay is
infrastructure you drive from a terminal, and it is a separate product from Gleipnir, which
has the wolf-and-chain badge. Relay and Gleipnir share a palette, not a crest.

| File | Use |
|---|---|
| `relay-wordmark-light.svg` / `.png` | On light backgrounds: near-black `relay`, teal `#0a8276` cursor |
| `relay-wordmark-dark.svg` / `.png` | On dark backgrounds: cream `#ece6da` `relay`, teal `#4fb3a8` cursor |
| `relay-icon.svg`, `relay-icon-512.png`, `relay-icon-32.png` | Square spaces (favicon, avatar, app icon): cream `r_` on a teal `#0a8276` rounded square; works on either background |

Prefer the SVGs. The PNGs are transparent exports for places that cannot take SVG.

## Rules

- **One accent.** Teal appears only on the cursor (or as the icon's ground). The letters are
  near-black `#1a1a1a` on light and cream `#ece6da` on dark.
- **Teal is a brand colour, not a UI colour.** It lives inside these images only. It is not
  one of the Console's semantic colours (`console.css`), and the mark adds no CSS token.
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
