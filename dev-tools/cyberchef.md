# CyberChef

> The "cyber swiss-army knife": a browser-based workbench for encoding,
> decoding, encryption, compression, and data manipulation — drag operations
> into a recipe and watch the output update live.

- **Link:** https://github.com/gchq/CyberChef
- **Type:** open source
- **Platform:** cross-platform (runs entirely in the browser; hosted or offline)

## Description

CyberChef, built by GCHQ, chains small operations ("bakes" a recipe) to
transform data without writing code. Base64, hex, URL and HTML encoding,
XOR/ROT/AES/RSA, gzip/zlib, JWT decoding, magic auto-detection of unknown
encodings, regex extraction, hashing — hundreds of operations you can stack and
reorder. It's the fastest way to answer "what is this blob and what's inside
it?" during CTFs, malware triage, log analysis, and day-to-day decoding. Because
it's client-side, you can run it fully offline so sensitive data never leaves
your machine.

## Installation

```bash
# Just use the hosted version — no install needed:
#   https://gchq.github.io/CyberChef/

# Or run it locally/offline: grab a release build and open index.html
git clone https://github.com/gchq/CyberChef.git
```

## Typical workflow

1. Drop your data into the **Input** pane (type, paste, or drag a file).
2. Drag **operations** from the left list into the **Recipe** pane.
3. Reorder/tweak operation arguments — the **Output** updates as you go.
4. Stuck on unknown data? Add the **Magic** operation to auto-detect likely
   encodings and suggest a recipe.
5. Save or share the recipe via the URL, or export it for reuse.

Common recipes: `From Base64` → `From Hex` → `Gunzip`; `Magic` on a mystery
string; `JWT Decode` on a token; `XOR Brute Force` on obfuscated bytes;
`Extract URLs` / regex over a log.

## Notes & references

- Hosted instance: https://gchq.github.io/CyberChef/ — works offline once
  loaded; also downloadable as a single-page release for air-gapped use.
- Source and releases: https://github.com/gchq/CyberChef
- The **Magic** operation is the killer feature for unknown data — it scores
  candidate decodings so you don't have to guess.
- Pairs well with command-line tools like [jq](jq.md) for JSON and
  [7-Zip](misc-utilities.md) for archives when data outgrows the browser.
- This is the canonical CyberChef page — other categories cross-link here for
  encoding/decoding and crypto data operations.
