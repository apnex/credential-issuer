---
id: unminted
category: component
title: credential-issuer - the credentials a caller presents to reach a hub, issued from authority the host accepts
status: draft
hydrate-when: Clients must be admitted to a service they connect to directly, and you are about to hand out long-lived tokens, codes or cookies for the service to check
sovereignty: internal
supersedes: []
related: [C0, A3]
---

# credential-issuer

The contract of record for credential-issuer: what a consumer can depend on, admitted to zorg's component set by the director's rulings `D38` and `D39` in zorg's `docs/DECISIONS.md`; its vision is ratified (zorg's `D40`), and its design is specified in `CIss1` to `CIss5` below (zorg's `D47`, `D59` to `D63`, `D71` to `D73`).\
It also carries the fields of a mission-kit registry entry, and that entry is generated from this file when the component is filed, never written as a second copy.\
The registry id is unminted on purpose; one is minted only when the entry is admitted to the registry.

---

## Duty

Issue the credentials a caller presents to reach a hub, from authority the host accepts.

---

## Contract

What a consumer can depend on, one capability per row.\
A capability is named for what it offers, not for who offers it, so two components that provide the same capability share its name, and the overlap is visible.\
**Provides** means this component implements the capability; **carries from X** means it passes X's capability through its own interface.\
**Requires** names the capabilities of other components a row depends on, as `component:capability`, so a census can follow an application's demand down through the components it reaches.\
A capability of another component marked *asked* does not exist yet and is requested of it.\
The trait column names any trait a system takes on by using the capability.

| Capability | Relation | Requires | What a consumer can depend on | Trait |
|---|---|---|---|---|
| `standing-code` | provides | `caller-identity:verified-principal`, `shape-check:plain-json-value` | A person the host's verifiers prove signed in can mint a code for an identity the host's rule lets them hold, shown once and kept only as a hash, list the codes they hold, and revoke one; a revoked or expired code yields no admission key from the moment it is revoked or expires. | `T1` when codes are kept durably |
| `admission-key-issue` | provides | `caller-identity:verified-principal`, `shape-check:plain-json-value` | A caller proving itself with a sign-in the host's verifiers accept, or with a standing code, whose principal the host's rule allows for the hub it names, is given a key naming that principal, that hub and the caller's node, usable once and for about a minute; an admission key is never accepted as proof for another; a refusal gives no key and a reason. | none |
| `fresh-key-per-dial` | provides | `agp:dialer-credential-source` (asked), `shape-check:plain-json-value` | Before every connection a client's connection holder opens, a reconnection included, it obtains a new key with the proof the application supplies, presents it once and only to the hub it names, and keeps it no longer; it presents a standing code only to the issuer; a failure to obtain a key ends that attempt with a reason, and nothing is dialled. | none |
| `single-use-admission` | provides | `agp:peer-identity-evidence`, `agp:admission-credential` (asked), `agp:session-close` (asked), `shape-check:plain-json-value` | An admission key admits at most one session, whoever presents it first; every later use is refused and reported, and while the key is live the session that used it first is named to the host, which closes it through the transport; a key for another hub or another node, an expired key, a standing code, and a key issued before the redeemer last started are refused. | none |
| `admission-key-verifier` | provides | `shape-check:plain-json-value` | Given one of its own admission keys and the admission's context, the redeemer answers as a verifier the host gives caller-identity: the principal the key was issued for, proved, with its issuer, or a refusal with a closed reason; caller-identity, not this component, records the session's principal, and the verifier never returns the key or any secret in it. | none |
| `preshared-key-secret` | provides | `agp:preshared-key-resolution` (asked) | On a pre-shared-key path, an admission key carries a fresh secret that the hub resolves from the key's identity without completing anything, so the handshake proves possession and the secret never crosses the wire; seeing a key's identity never uses the key. | none |
| `key-reuse-report` | provides | none | Each refused second use is reported once, to a sink the host supplies, with a fingerprint of the key, its principal, hub and node, and both sessions; never the key, its secret or the proof that obtained it. | none |

Admission keys and their single-use records are held in memory for about two minutes, so only `standing-code` brings a trait, and then only where codes are kept durably.\
It coordinates no actors and contains no model.\
Its shapes are OAuth 2.0's wherever one fits and is cheap (zorg's `D39`): the JWT access-token profile's claims for a key that is a token (RFC 9068), a token endpoint's behaviour for the issuing route, token exchange for a sign-in (RFC 8693), a client-credentials-style request for a standing code, and OAuth's bearer rules where a key is a bearer (RFC 6750).

**Two limits, stated with the capabilities (zorg's `D39`, amending `D38`).**\
A revoked sign-in stops new keys at once only where the application keeps a record of revoked sign-in sessions for the issuer to consult, since a sign-in assertion checked offline cannot see a logout.\
A second use closes the first session only while the key is live; afterwards it is refused as expired and reported, with nothing to close by.

---

## Design

Each declaration names the exit criterion that proves it and the contract test files that exercise it (`D10-E2`).\
A bounded identifier (`issuer`, `principal`, `instanceBinding`, `redemptionId`, `session`, `hub`, `codeId`) is a string of 1 to 256 Unicode scalar values (`Array.from(value).length` from `1` to `256`) containing no control character (`U+0000..U+001F` or `U+007F..U+009F`) and no lone surrogate (`U+D800..U+DFFF`), with `issuer !== "agp-transport"`; a machine or proxy `identity` matches `/^[a-z0-9][a-z0-9-]{0,62}$/` (`EM1`), and a `node` matches `/^([a-z0-9][a-z0-9-]{0,62})\.([0-9a-f]{16})$/` (`PX1`, `D60`), whose prefix before the dot is its claimed `identity`.\
Every value returned by a host callback (`allowStandingCode`, `allowAdmissionKey`, `isSignInRevoked`, `StandingCodeStore.load`, `recordAdmissionRedemption`, `readAdmissionUse`, `issueKey`, `readAdjacencies`, `notifyCredentialChange`) after any declared native `Promise` completion is read as plain data through `shape-check`'s `readPlainJson` and `observePromises` (zorg's `D54`, `D55`), never invoking a getter or non-native thenable and consuming any reachable native promise rejections within the reader's bound.

**CIss1 - Standing codes and durable storage (`standing-code`, `D38`, `D39`, `D54`, `D55`, `D73`).**\
Standing codes use a restart-stable wall-clock port `wallClock?: { nowMs(): number }` (defaulting to `Date.now()` in `src/clock-adapter.ts`, so no source file outside `*-adapter.ts` touches `Date.now()`) for `createdAtMs`, `expiresAtMs` and `revokedAtMs` (`expiresAtMs !== null && wallClock.nowMs() >= expiresAtMs` is expired), while admission keys and leases use the shared monotonic `ClockPort` (`clock?: ClockPort`, defaulting to `defaultClock` in `src/clock-adapter.ts`).\
A `StandingCodeRecord` is a plain object `{ codeId, codeHash, identity, minterPrincipal, minterIssuer, createdAtMs, expiresAtMs, revokedAtMs }` where `codeHash` is the 64-character lowercase hexadecimal SHA-256 digest of the UTF-8 standing-code secret (`ci_code_<64 lowercase hex digits>`); the raw code secret is never stored.\
`StandingCodeStore` offers `load(): readonly StandingCodeRecord[]` and `save(records: readonly StandingCodeRecord[]): void`: `createMemoryStandingCodeStore(initialRecords?)` keeps deep-frozen plain records in memory; `createFileStandingCodeStore(filePath)` in `@apnex/credential-issuer/machine` (`src/machine-adapter.ts`) refuses symbolic links or directories at `filePath` or `${filePath}.tmp` with a coded `Error` (`code: "code-store-unwritable"`), validates `load()` records through `readPlainJson` after a leading `{"store":"credential-issuer-codes","version":1}` header line (throwing an `Error` with `code: "code-store-corrupt"` on any missing/bad header, malformed JSON, non-plain line, invalid field or duplicate `codeId` or `codeHash`, never resetting or resurrecting codes, and returning `[]` when `filePath` is absent), and commits every `save(records)` synchronously before returning by writing the header and canonical JSON record lines to `${filePath}.tmp` (`O_CREAT | O_EXCL | O_WRONLY`, mode `0600`, unlinking a stale regular `${filePath}.tmp` first if present), calling `fdatasyncSync`, closing the descriptor, calling `renameSync("${filePath}.tmp", filePath)`, and calling `fsyncSync` on the parent directory (throwing a coded `Error` with `code: "code-store-unwritable"` if any write step fails).\
`issuer.mintStandingCode({ proof, identity, expiresAtMs? })` rejects any admission key or standing code passed as `proof` (`{ ok: false, code: "proof-refused" }`), verifies `proof` via `caller-identity`'s `verifyCredential(verifiers, proof, { clock })`, checks `isSignInRevoked?({ principal, issuer, session })` (refusing as `"proof-refused"` if unverified, expired or revoked), validates `identity` (`"invalid-identity"`) and optional `expiresAtMs` (`"invalid-expiry"` if non-finite or `<= wallClock.nowMs()`), checks `allowStandingCode({ minterPrincipal, minterIssuer, identity })` (read as a plain boolean via `readPlainJson` and `observePromises`, defaulting to `minterPrincipal === identity` when `allowStandingCode` is omitted, and refusing as `"forbidden-identity"` unless `true`), and in the serialized commit turn re-verifies sign-in revocation and expiry, mints a 32-byte random secret `ci_code_<64 hex>` and `codeId`, persists the updated record list through `standingCodeStore.save` before mutating in-memory state (returning `{ ok: false, code: "code-store-unwritable" }` with in-memory state unchanged if `save` throws), and returns `Object.freeze({ ok: true, codeId, code, identity, minterPrincipal, minterIssuer, createdAtMs, expiresAtMs: expiresAtMs ?? null })`.\
`issuer.listStandingCodes({ proof })` verifies `proof` and `isSignInRevoked` (`"proof-refused"`) and returns `{ ok: true, codes }` with the caller's public `{ codeId, identity, minterPrincipal, minterIssuer, createdAtMs, expiresAtMs, revokedAtMs }` records (never `code` or `codeHash`).\
`issuer.revokeStandingCode({ proof, codeId })` verifies `proof` and `isSignInRevoked` (`"proof-refused"`), requires `codeId` to exist for `(minterPrincipal, minterIssuer)` (`"not-found"`), sets `revokedAtMs` on `wallClock` and persists via `standingCodeStore.save` before updating in-memory state (`"code-store-unwritable"` on write failure), so a revoked or expired standing code yields no admission key from the moment it is revoked or expires.\
Tested by: `D10-E2`, in `test/contract/standing-code.test.js`, covering sign-in verification, `allowStandingCode`, SHA-256 hashing without raw secret storage, `listStandingCodes`, `revokeStandingCode`, wall-clock expiry, `createMemoryStandingCodeStore` and `createFileStandingCodeStore` across restarts, symlink/directory/write-failure `"code-store-unwritable"` fail-closed checks, corrupt header/line/duplicate `"code-store-corrupt"` checks, and `D54`/`D55` plain-data callback protection.

**CIss2 - Exclusive node leases and admission-key issuance (`admission-key-issue`, `preshared-key-secret`, `A1`, `D38`, `D39`, `D60` to `D63`, `D71`, `D73`).**\
Active node leases in `credential-issuer` are indexed by **`(hub, node)`** (`D60` item 3, `D61`): at most one `(issuer, principal, instanceBinding)` owns an active lease for a given `(hub, node)` at any time.\
`issuer.issueAdmissionKey(request)` accepts OAuth 2.0 token-exchange requests for sign-in proofs (`grantType: "urn:ietf:params:oauth:grant-type:token-exchange"`, `subjectToken`) and client-credentials requests for standing codes (`grantType: "client_credentials"`, `clientSecret`), as well as `{ proof: { kind: "sign-in", token } | { kind: "standing-code", code } }`, together with `hub`, `node`, optional `proofMode` (`"native-tls13-external-psk-v1"` default, or `"bearer"`), and optional `continuationSecret`.\
It rejects any admission key presented as proof (`{ ok: false, code: "proof-refused" }`), validates `hub === options.hub` (`"wrong-hub"`), `node` format `<identity>.<16 lowercase hex>` (`"invalid-node"`), and `proofMode` (`"invalid-proof-mode"`), verifies either the sign-in proof via `verifyCredential` + `isSignInRevoked` or the standing code by SHA-256 `codeHash` (requiring `revokedAtMs === null`, `expiresAtMs === null || wallClock.nowMs() < expiresAtMs`, and `record.identity === nodePrefix`, else `"proof-refused"`), and checks `allowAdmissionKey({ principal, issuer, hub, node, proofKind, proofMode })` (read as a plain boolean via `readPlainJson` and `observePromises`, refusing as `"policy-refused"` unless `true`).\
In the serialized commit turn, `issueAdmissionKey` re-verifies sign-in expiry and `isSignInRevoked` (or standing-code non-revocation and wall-clock expiry, refusing as `"proof-refused"` if invalidated while awaiting an async callback), sweeps reclaimable leases (`sweepLeases()`), and checks the active lease for `(hub, node)`:
- if no active lease exists for `(hub, node)`, checks `activeLeases.size < maxActiveLeases` and `totalReservedHandles < maxTotalHandles` (else refuses `{ ok: false, code: "lease-capacity" }` without evicting any live lease), allocates a new lease for `(hub, node)` with `issuer`, `principal`, a fresh 32-byte hex `continuationSecret` (`ci_cont_<64 hex>`, stored only as its SHA-256 hash), a unique `instanceBinding = "${generation}-${++nextAllocationId}"` (never reused for any later allocation or across restarts), and `lastActivityMs = clock.now()`;
- if an active lease exists for `(hub, node)`, requires `lease.issuer === issuer && lease.principal === principal` and a valid `request.continuationSecret` matching `lease.continuationSecretHash` (refusing any competing `(issuer, principal)` or missing/wrong `continuationSecret` for an active `(hub, node)` as `{ ok: false, code: "node-identity-conflict" }`), checks per-lease and total handle capacity (`lease.reservedHandles < maxHandlesPerLease` and `totalReservedHandles < maxTotalHandles`, else `"lease-capacity"`), and advances `lease.lastActivityMs = Math.max(lease.lastActivityMs, clock.now())`.\
It then mints a single-use key with `redemptionId = "${generation}-${++nextKeyId}"` (verifying printable ASCII `0x21..0x7E`, no NUL or whitespace, and `utf8ByteLength(redemptionId) <= maxPskIdentityBytes <= 127`, refusing as `"incompatible-psk-identity"` rather than truncating if `maxPskIdentityBytes` is exceeded), a 32-byte `Uint8Array` `secret` (`secret.byteLength === 32`), `validBeforeMonotonicMs = clock.now() + keyLifetimeMs` on the shared `ClockPort`, `keyFingerprint`, `bearerToken`, `continuationSecret`, and RFC 9068 claims (`iss`, `sub`, `aud`, `client_id`, `jti`, `exp`).\
Tested by: `D10-E2`, in `test/contract/admission-key-issue.test.js` and `test/contract/preshared-key-secret.test.js`, covering RFC 8693 sign-in and `client_credentials` standing-code issuance, admission-key-as-proof rejection, `isSignInRevoked` rechecked at serialized commit, `(hub, node)` lease exclusivity (`"node-identity-conflict"` on competing principals or missing/wrong `continuationSecret`, `"lease-capacity"` without live eviction), 32-byte `Uint8Array` secret and `<= 127`-byte printable ASCII `pskIdentity`, and `D54`/`D55` plain-data protection.

**CIss3 - Non-consuming PSK lookup, proof completion, single-use termination and reuse reporting (`preshared-key-secret`, `single-use-admission`, `key-reuse-report`, `A2`, `D47`, `D63`, `D71`, `D72`, `D73`).**\
`redeemer.resolvePsk(pskIdentity, attempt?)` (`A2`) synchronously validates `pskIdentity` (non-empty printable ASCII `0x21..0x7E`, `<= maxPskIdentityBytes <= 127` bytes) and looks up the key in the current process `generation`: if the key exists for `proofMode === "native-tls13-external-psk-v1"` and `hub === options.hub` within its retained window (`clock.now() < key.retainUntilMonotonicMs`), including a key already `"spent"`, `"uncertain"` or expired within that retention window, `resolvePsk` returns `{ kind: "resolved", secret: new Uint8Array(key.secret), lookupRef }` (reusing the same `lookupRef` on repeated callbacks for the same `attempt` and `pskIdentity`) without marking an unspent key spent and without reporting reuse or closing any session at lookup time, so a selector-only probe without the 32-byte secret never spends a key, reports reuse or closes a live session, while a second presenter holding the secret completes the handshake and is caught at `completePskProof`.\
`redeemer.completePskProof(attempt, proof)` (and `redeemer.redeemBearer(use, bearerToken, remoteNodeId?)` for `"bearer"` keys) verifies exact object identity (`proof.arrival === attempt.arrival && proof.lookupRef === attempt.lookupRef`) and runs the serialized non-yielding transaction:
- if the key is already `"spent"` or `"uncertain"` (and `use.lifecycle !== key.firstUse?.lifecycle`): refuses the second presentation (`"refused"`), determines `live = clock.now() < key.validBeforeMonotonicMs`, calls `key.firstUse.control.requestAdmissionTermination()` (`agp:session-close`) if and only if `live` is `true`, and emits one frozen `KeyReuseReport` `{ keyFingerprint, principal, issuer, hub, node, firstRedemptionId: key.redemptionId, secondRedemptionId: key.redemptionId, firstSessionStopped: live && key.firstUse !== null }` to `onKeyReuse` (guarded with `try / catch` and `observePromises`, never exposing the raw key, its 32-byte secret, or the proof that obtained it);
- if the key is `"unspent"`, synchronously checks the issuing `generation`, active `(hub, node)` lease (`lease.instanceBinding === key.instanceBinding`), proof mode, target `hub`, `remoteNodeId === key.node` (when provided), `clock.now() < key.validBeforeMonotonicMs`, and `use.lifecycle` uniqueness (returning `"redeemed"` without a new slot if `use.lifecycle` is already `"committed"` for this exact `redemptionId`, and refusing if `use.lifecycle` is registered for another key), pre-inserts `slot` in state `"prepared"`, and calls `use.redemption.recordAdmissionRedemption(key.redemptionId, { clock, validBeforeMonotonicMs: key.validBeforeMonotonicMs })` (read through `readPlainJson` and `observePromises`):
  - on `{ kind: "recorded" }`, synchronously flips `slot.state = "committed"`, `key.state = "spent"`, `key.firstUse = slot`, and updates `lease.lastActivityMs = Math.max(lease.lastActivityMs, clock.now())` in place, returning `"redeemed"`;
  - on an explicit unrecorded refusal (`"authorization-expired"`, `"expired"`, `"invalid-authorization"`, `"invalid-redemption"`, `"inactive"`, `"capacity"`) or `"already-recorded"`, removes the newly `"prepared"` slot and leaves `key.state = "unspent"` (or preserves the original committed registration on `"already-recorded"`), returning `"refused"`;
  - if `recordAdmissionRedemption` throws or returns any other shape, flips `slot.state = "uncertain"` and `key.state = "uncertain"`, sets `key.firstUse = slot`, calls `use.control.requestAdmissionTermination()` (`observePromises`), and returns `"refused"`.\
`redeemer.beginPskArrival(uses, callbacks, arrival)` (`A2`, `D72`) synchronously calls `uses.reserveAdmissionUse()` before any TLS, lookup or proof work (returning `{ kind: "refused", reason: "capacity" | "inactive" }` when unavailable, and calling `use.finishAdmissionAcquisition()` if setup fails before returning an attempt), and in `acceptPskChannel(channel, carrierAcquisitionSettled?)` returns normally first and then runs the host continuation that seals handoff (`use.sealAdmissionHandoff(channel)`) and calls `callbacks.acceptAdmission(seal.handoff)` (or calls `requestAdmissionTermination()` and disposes `channel` on a non-redeemed proof, refused seal or throwing `acceptAdmission`), calling `use.finishAdmissionAcquisition()` once `carrierAcquisitionSettled` and the host's own offer/callbacks/refusal-disposal settle (`compositionSettled`), without waiting for node adoption or node-owned channel disposal.\
Tested by: `D10-E2`, in `test/contract/preshared-key-secret.test.js`, `test/contract/single-use-admission.test.js` and `test/contract/key-reuse-report.test.js`, covering non-consuming `resolvePsk`, selector-only lookup vs authenticated second presentation, live vs expired reuse (`requestAdmissionTermination` called only while `clock.now() < validBeforeMonotonicMs`), secret-free `KeyReuseReport`, all `recordAdmissionRedemption` outcomes (`recorded`, explicit refusals, `already-recorded`, throw/malformed `"uncertain"`), restart generation refusal, and `D72` `compositionSettled` completion.

**CIss4 - Dual lookup and 4-condition lease reclamation (`admission-key-verifier`, `A5`, `D62`, `D63`, `D71`, `D73`).**\
`redeemer.verifyRedeemed({ redemptionId, lifecycle, remoteNodeId })` (`admission-key-verifier`, `A5`) validates its inputs and resolves a redeemed key for `caller-identity` only when its slot is `"committed"` under the current process `generation` and current active `(hub, node)` lease (`lease.instanceBinding === slot.instanceBinding`), both `slot.redemptionId === redemptionId` and exact object identity `slot.lifecycle === lifecycle` match, and `remoteNodeId === slot.node`, returning `Object.freeze({ ok: true, issuer: slot.issuer, principal: slot.principal, instanceBinding: slot.instanceBinding })` (or `{ ok: false, reasonCode: "EXPECTED_NODE_MISMATCH" }` when `remoteNodeId !== slot.node`, or `{ ok: false, reasonCode: "SECURITY_EVIDENCE" }` otherwise, never returning the key or any secret).\
`redeemer.sweepLeases()` polls each registered `slot.lifecycle.readAdmissionUse()` inside `try / catch` through `readPlainJson` and `observePromises`, retaining the slot and lease on `"pending"`, `"admitted"`, `"established"` or any throw or malformed return, recording `slot.terminalObservedAtMs = nowMs` and advancing `lease.lastActivityMs = Math.max(lease.lastActivityMs, nowMs)` on the first valid `{ state: "terminal" }` observation, compacting terminal slots once `nowMs >= slot.validBeforeMonotonicMs`, and reclaiming the lease for `(hub, node)` only when all four `D62` conditions hold together in the same synchronous turn: (1) no `"unspent"` key under `lease.instanceBinding` has `nowMs < key.validBeforeMonotonicMs`, (2) no `"prepared"` or `"uncertain"` or pending/admitted slot under `lease.instanceBinding` remains non-terminal, (3) every `"committed"` slot under `lease.instanceBinding` has been observed `{ state: "terminal" }`, and (4) `nowMs - lease.lastActivityMs >= reconnectGraceMs`, after which a subsequent issuance for `(hub, node)` receives a new, never-reused `instanceBinding`.\
Tested by: `D10-E2`, in `test/contract/admission-key-verifier.test.js`, covering dual `redemptionId` + exact `lifecycle` object identity verification, `"EXPECTED_NODE_MISMATCH"` vs `"SECURITY_EVIDENCE"` denials, composition with `@apnex/caller-identity` in `"authenticated"` mode, and all four `D62` lease-reclamation conditions (including thrown/malformed `readAdmissionUse()` retaining the lease and close-activity grace anchoring).

**CIss5 - Client fresh-key-per-dial and refusal observation (`fresh-key-per-dial`, `A3`, `A4`, `D71`, `D73`).**\
`createCredentialPresenterTarget(options)` implements `createCredentialAttempt(request, permit)` as a synchronous no-I/O constructor that captures an immutable snapshot of the caller's current primary proof (and stored `continuationSecret` for `(hub, node)`) and transfers custody of `permit` (`CredentialCarrierReservation`) only on normal return (leaving `permit.releaseUnused()` uncalled and accessible to the caller if construction throws).\
`attempt.prepareCredential(signal?)` runs at most once under the single acquisition deadline, calls `issueKey` to fetch a fresh single-use key for `(hub, node)` (presenting a standing code only to `issueKey`, never caching or reusing a key across attempts, and storing the returned `continuationSecret` for `(hub, node)` renewals), and returns `{ kind: "prepared", keyMeta, connection }`, `{ kind: "issuer-refused", code }` (only for an explicit current issuer refusal for the captured proof and bound `(hub, node)`), or `{ kind: "issuer-unavailable", reason }` (for transport/network failures, capacity, expired/malformed keys or exceptions, dialling nothing on either refusal).\
`connection.connect(signal?)` runs at most once, zeroes out the one-shot key reference, and invokes `connectWithKey(key, signal)`; `attempt.dispose()` is idempotent and enforces `A3`'s three-case carrier-permit cleanup: (1) when no socket was created, `dispose()` releases `permit.releaseUnused()` only after all in-flight `prepareCredential` / `issueKey` work and potential socket creators have settled, (2) when an untransferred socket was created, `dispose()` waits for that socket's exact native close before releasing `permit.releaseUnused()`, and (3) after channel custody has transferred to the node (`markChannelTransferred()`), `dispose()` settles only acquisition-owned work, never closes the transferred channel, and never refunds or discharges `permit`.\
`observeAdjacencyRefusal(options)` (`A4`) subscribes to `events()` before its initial read of `readAdjacencies()` (re-reading on wakes and resynchronizing on gaps), maps only a current `credential.phase === "issuer-refused"` to `operation-proxy`'s `"admission-refused"`, and in `updateProofAndRearm(newProof)` installs the new proof before calling `notifyCredentialChange(adjacencyId)` and requires `snapshot.credential.generation >= receipt.generation` (accepting a newer committed generation or `"inactive"` state, and never restoring an older refusal).\
Tested by: `D10-E2`, in `test/contract/fresh-key-per-dial.test.js`, covering fresh key per dial and reconnect with `continuationSecret`, standing code presented only to the issuer, constructor throw leaving `permit.releaseUnused()` to the caller, all three `dispose()` permit-custody cases, and `observeAdjacencyRefusal` subscribe-before-read ordering, `"issuer-refused"` mapping and `generation >= receipt.generation` rearming.

---

## Reference

This repository, `apnex/credential-issuer`, private until its first working code is certified.\
The package `@apnex/credential-issuer` exports `createCredentialIssuer`, `createMemoryStandingCodeStore`, `createCredentialPresenterTarget`, and `observeAdjacencyRefusal`, and `@apnex/credential-issuer/machine` exports `createFileStandingCodeStore`, as `export-map.json` records.\
It depends on `@apnex/shape-check` and `@apnex/caller-identity` through `file:` links, takes AGP's types from `@agp/core` as a peer dependency through a `file:` link to AGP's checkout, imports nothing from AGP at run time, and imports no module particular to one runtime outside files whose name ends `-adapter.ts`.

---

## Fit criteria

### Does my project want this at all

- Clients connect directly to a service and hold their connection open, and the service must decide, as each connection opens, whether to admit it.
- Some clients are people signed in through a provider, and some are machines with no person present.
- A credential stolen from a client, a log or a URL must be worth as little as possible.

### Does it meet my requirement

- A service sees one kind of credential from every client.
- No credential a service accepts admits twice.
- The host chooses its sign-in providers, its verifiers and its rule on who may connect; none is built in.

**It is the wrong tool when**

| You need | Reach elsewhere, because credential-issuer is |
|---|---|
| sign-in pages, accounts or passwords | not an identity provider |
| who a request comes from, request by request | not a verifier of requests; that is caller-identity |
| what a caller may read or change | not an authority; that is the application's policy |
| tokens for many services, consent or delegation | not a general authorization server |
| a protected channel | not a transport |

---

## Adjustment policy

Internal and sovereign, so a fit gap has somewhere to go.

1. Record a measured gap where both sides can see it.
2. Resolve it by adjusting credential-issuer, so every consumer gets the change, or by fracturing it when the gap reveals a second duty.
3. Never fork.

Proofs reach it through verifiers the host supplies, and keys reach a hub through the transport, so a new sign-in provider is a verifier and a new transport profile is a carriage, rather than a change to credential-issuer.

---

## Edges

**Composes:** nothing registered.

**Consumes, through a declared contract:**

- `caller-identity`: `verified-principal`
- `shape-check`: `plain-json-value`
- `agp`: `peer-identity-evidence`; and, asked, `dialer-credential-source`, `admission-credential`, `session-close`, `preshared-key-resolution`

**Composed-by:** nothing yet.\
Its first consumers, once built, are zorg's hub and command line and zorg's web canvas, and drawv2 when its live channel runs over AGP.

The registry's edge vocabulary has no edge for one component using another's contract without containing it; see the note in operation-call's entry.
