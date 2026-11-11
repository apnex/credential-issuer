# credential-issuer

Issue the credentials a caller presents to reach a hub, from authority the host accepts.

**Status: built.**\
Its vision is ratified (zorg's `D40`), and its contract (`CIss1` to `CIss5`) specifies standing codes, single-use admission keys, exclusive `(hub, node)` leases, non-consuming pre-shared-key resolution, exact-use redemption and reuse reporting, dual `redemptionId` + `lifecycle` verification, and fresh-key-per-dial client presentation.

- `VISION.md` - why it exists, and what it will never be.
- `CONTRACT.md` - what a consumer can depend on, one capability per row.
- `docs/DECISIONS.md` - the rulings about this component.

It belongs to a component set first composed by zorg (`apnex/zorg`), and is released only by its own CI, as a tarball attached to a GitHub release with its SHA-512 beside it, which a consumer names in its `package.json`: `https://github.com/apnex/credential-issuer/releases/download/v0.1.0/apnex-credential-issuer-0.1.0.tgz` for `0.1.0`.

It depends on `@apnex/shape-check` and `@apnex/caller-identity` through their release files, and takes AGP's types as an optional peer, `@agp/core` `>=0.1.0`, while its tests take AGP through a `file:` link to an AGP checkout beside it, installed and built first, since AGP commits no `dist/`.

To run the tests from clean checkouts:
```sh
(cd ../agp && npm ci && npm run build)
(cd ../shape-check && npm ci && npm run build)
(cd ../caller-identity && npm ci && npm run build)
npm ci
npm test
```
