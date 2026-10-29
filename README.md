# credential-issuer

Issue the credentials a caller presents to reach a hub, from authority the host accepts.

**Status: built.**\
Its vision is ratified (zorg's `D40`), and its contract (`CIss1` to `CIss5`) specifies standing codes, single-use admission keys, exclusive `(hub, node)` leases, non-consuming pre-shared-key resolution, exact-use redemption and reuse reporting, dual `redemptionId` + `lifecycle` verification, and fresh-key-per-dial client presentation.

- `VISION.md` - why it exists, and what it will never be.
- `CONTRACT.md` - what a consumer can depend on, one capability per row.
- `docs/DECISIONS.md` - the rulings about this component.

It belongs to a component set first composed by zorg (`apnex/zorg`), and is private until its first working code.

It depends on `@apnex/shape-check` and `@apnex/caller-identity` through `file:` links, and takes AGP's types as a peer through a `file:` link to an AGP checkout beside it, each installed and built first, since none commits its `dist/`.

To run the tests from clean checkouts:
```sh
(cd ../agp && npm ci && npm run build)
(cd ../shape-check && npm ci && npm run build)
(cd ../caller-identity && npm ci && npm run build)
npm ci
npm test
```
