# Decisions

One ruling per entry, append-only.\
A ruling is never edited; a later one supersedes it and says so.

Rulings that shape this component together with others are held in zorg's `docs/DECISIONS.md`, and cited here as "zorg's `Dn`".

---

## D1 - The component stands in its own repository

**Ruled by:** the director, 2026-10-10 (zorg's `D38` and `D39`).\
**Affects:** this repository.

**Ruling.**\
This component, credential-issuer, is sovereign and stands in its own repository, private until its first working code, on the terms of zorg's `D16`.\
Its contract of record is `CONTRACT.md` (zorg's `D17`), and its vision becomes enduring only when the director ratifies it.\
Its shapes follow OAuth 2.0's wherever one fits and is cheap (zorg's `D39`).

**Why.**\
It holds no application's content, so it is a shared component even while no application has built it (zorg's `D35`), and zorg's command line, zorg's web canvas and drawv2 all need it (zorg's `D38`).

---

## D2 - The vision is ratified

**Ruled by:** the director, 2026-10-10 (zorg's `D40`).\
**Affects:** `VISION.md`.

**Ruling.**\
The vision is ratified at `924a935`, after two rounds of cold reading by two model families, and its status line says so.\
From here it changes only by a recorded decision, absorbed into it.

---

## D3 - The first release, 0.1.0, carrying the five shared fixes

**Ruled by:** the director, 2026-11-10 (draw's `H31-5`, on zorg's agreement: draw's request, `upstream/drawv2-shared-component-fixes-request.md`, and zorg's reply, `upstream/drawv2-shared-component-fixes-reply.md`, whose answers bind).\
**Affects:** `package.json` and its lockfile, `.nvmrc`, `.github/workflows/gate.yml` and `release.yml`, `tools/consumer-test.mjs`, `CONTRACT.md`'s frontmatter and Reference, and `README.md`; nothing in `src/`, and nothing the component does.

**Ruling.**\
The five fixes every consumer of the components zorg maintains needs, made by draw's builders on zorg's agreement, none changing what the component does:
1. A release in the pinned-file form, gated by CI: `gate.yml` runs `npm test` and `npm run docs:check` on every push and pull request on Node 22 and 24, then the consumer test on Node 22 -- the package packed, installed into an empty project with `--omit=dev`, no AGP package installed, and every export imported by name; `release.yml`, on a tag `v<version>` that the repository's `release tags` ruleset protects, runs the gate, packs the package once, attaches the `.tgz` and its `.sha512` to a draft GitHub release, downloads both back and compares them, and only then publishes, immutable releases being enabled for the repository before its first tag; the first release is `0.1.0`.
2. A Node 22 floor: `engines` `>=22`, and `.nvmrc` `22`.
3. Dependencies between components as release files: `@apnex/caller-identity` and `@apnex/shape-check` from `file:` links to their `0.1.0` release files, each pinned in the lockfile by its integrity.
4. AGP declared as what it is: `@agp/core` kept as a peer, its `file:` link unchanged, and made optional (`peerDependenciesMeta`), so a consumer that does not run AGP installs none of it, while the tests' `@agp/core` stays a `file:` link in `devDependencies`.
5. The contract's frontmatter brought to mission-kit's: `id: C10`, `status: active`, and the sentences that said the id was unminted and the repository private until its first working code restated.

**Choices made at build.**
- `private: true` stays: it stops publishing to the npm registry, and `npm pack` packs the package with it.
- The style rules `npm run docs:check` holds are vendored in `tools/`, so CI fetches no mission-kit checkout.
- `package.json` carries one `overrides` entry, pointing caller-identity's optional `@agp/core` peer at this repository's own `@agp/core`: caller-identity's `0.1.0` release declares that peer as `file:../agp/packages/core`, which npm resolves from the installed package's own folder and so never matches the AGP beside this repository, and without the entry `npm install` refused the tree (`ERESOLVE`); an `overrides` entry binds this repository's own install alone, never a consumer's, and this repository's own peer, declared the same way, is left as zorg's answer 3 and its test have it.
- In CI this repository is checked out into a folder of its own and `apnex/agp` beside it, both inside the workspace, since `actions/checkout` places a repository only there; AGP is checked out with its history and then at `b179b4f` by that short id, so no full commit id is written but the actions' own pins, and built with `npm --prefix ../agp ci && npm --prefix ../agp run build` before `npm ci`, so the `file:` links to `../agp/packages` resolve (zorg's answer 3).
- Its contract claims no browser runtime, so the consumer test imports the package in Node alone, loading nothing in Chrome.

**Why.**\
Draw takes components as public GitHub release files pinned by hash and runs Node 22 in production (draw's `H26-2`); a `file:` link builds only beside a checkout, and an AGP declared for install would make every consumer install it though every import of it is a type.

---

## D4 - 0.1.1: the optional AGP peer as a version range, and caller-identity's 0.1.1

**Ruled by:** the director, 2026-11-11 (draw's `H31-9`, on zorg's reply `upstream/drawv2-planning-contract-drafts-reply.md`, which asked for this change).\
**Affects:** `package.json` and its lockfile, `README.md` and `CONTRACT.md`'s Reference; nothing in `src/`, and nothing the component does; a patch release, `0.1.1`.

**Ruling.**\
`peerDependencies["@agp/core"]` is `>=0.1.0`, where `0.1.0` declared `file:../agp/packages/core`; it stays optional (`peerDependenciesMeta`), and the tests still take `@agp/core` as a `file:` link in `devDependencies`, as zorg's answer 3 has it (`D3`).\
A `file:` peer is resolved by npm from the installed package's own folder, where no AGP is, so the `0.1.0` release's peer matched no host's `@agp/core`, and every consumer that installed AGP beside it was refused by `npm install` (`ERESOLVE`); a range is matched by the host's own `@agp/core`, wherever it came from.\
`@apnex/caller-identity` is its `0.1.1` release file, whose peer is the same range (caller-identity's `D4`), and the `overrides` entry `D3` added to get past caller-identity's `0.1.0` peer is removed, since nothing needs it now: `npm install` resolves the tree without it.

**Why.**\
A consumer that runs AGP is the consumer this component serves; the fix was found in the `0.1.0` wave and asked for by zorg, whose surface test already accepts `*`, `>=0.1.0` or `^0.1.0`; `>=0.1.0` names the first AGP this component is written against without capping the host's.

