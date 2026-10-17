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

The contract of record for credential-issuer: what a consumer can depend on, admitted to zorg's component set by the director's rulings `D38` and `D39` in zorg's `docs/DECISIONS.md`; its vision is ratified (zorg's `D40`), and this contract is a draft until its design is verified.\
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
| `standing-code` | provides | `caller-identity:verified-principal` | A person the host's verifiers prove signed in can mint a code for an identity the host's rule lets them hold, shown once and kept only as a hash, list the codes they hold, and revoke one; a revoked or expired code yields no admission key from the moment it is revoked or expires. | `T1` when codes are kept durably |
| `admission-key-issue` | provides | `caller-identity:verified-principal` | A caller proving itself with a sign-in the host's verifiers accept, or with a standing code, whose principal the host's rule allows for the hub it names, is given a key naming that principal, that hub and the caller's node, usable once and for about a minute; an admission key is never accepted as proof for another; a refusal gives no key and a reason. | none |
| `fresh-key-per-dial` | provides | `agp:dialer-credential-source` (asked) | Before every connection a client's connection holder opens, a reconnection included, it obtains a new key with the proof the application supplies, presents it once and only to the hub it names, and keeps it no longer; it presents a standing code only to the issuer; a failure to obtain a key ends that attempt with a reason, and nothing is dialled. | none |
| `single-use-admission` | provides | `agp:peer-identity-evidence`, `agp:admission-credential` (asked), `agp:session-close` (asked) | An admission key admits at most one session, whoever presents it first; every later use is refused and reported, and while the key is live the session that used it first is named to the host, which closes it through the transport; a key for another hub or another node, an expired key, a standing code, and a key issued before the redeemer last started are refused. | none |
| `admission-key-verifier` | provides | none | Given one of its own admission keys and the admission's context, the redeemer answers as a verifier the host gives caller-identity: the principal the key was issued for, proved, with its issuer, or a refusal with a closed reason; caller-identity, not this component, records the session's principal, and the verifier never returns the key or any secret in it. | none |
| `preshared-key-secret` | provides | `agp:preshared-key-resolution` (asked) | On a pre-shared-key path, an admission key carries a fresh secret that the hub resolves from the key's identity without completing anything, so the handshake proves possession and the secret never crosses the wire; seeing a key's identity never uses the key. | none |
| `key-reuse-report` | provides | none | Each refused second use is reported once, to a sink the host supplies, with a fingerprint of the key, its principal, hub and node, and both sessions; never the key, its secret or the proof that obtained it. | none |

Admission keys and their single-use records are held in memory for about two minutes, so only `standing-code` brings a trait, and then only where codes are kept durably.\
It coordinates no actors and contains no model.\
Its shapes are OAuth 2.0's wherever one fits and is cheap (zorg's `D39`): the JWT access-token profile's claims for a key that is a token (RFC 9068), a token endpoint's behaviour for the issuing route, token exchange for a sign-in (RFC 8693), a client-credentials-style request for a standing code, and OAuth's bearer rules where a key is a bearer (RFC 6750).

**Two limits, stated with the capabilities (zorg's `D39`, amending `D38`).**\
A revoked sign-in stops new keys at once only where the application keeps a record of revoked sign-in sessions for the issuer to consult, since a sign-in assertion checked offline cannot see a logout.\
A second use closes the first session only while the key is live; afterwards it is refused as expired and reported, with nothing to close by.

---

## Design owed

Not yet designed; this section lists what two independent design seats, of two model families, agreed and where they differed, so the design starts from it.\
Their designs are kept with zorg's evaluation records, outside this repository.

**Agreed.**

- The issuer runs in the application's own server process, so its availability is the hub's.
- The fetcher runs inside the function an application gives operation-proxy to build its caller (operation-proxy's `PX9`), so operation-proxy itself holds no credential; a browser's shared worker proves itself with the person's sign-in, and a machine's proxy with the standing code it alone reads.
- AGP is asked for three things: a credential source it calls once for every connection attempt, before the attempt's carrier opens; a one-shot place for the presented credential to reach the admission check, never in peer evidence; and a host's close of one exact session.
- On a pre-shared-key path, resolving a key's identity never uses the key; its use is recorded only after the handshake has proved possession.
- operation-proxy is asked for one refusal code, `admission-refused`, so a refused proof ends a command at once instead of looking like an unreachable proxy.
- caller-identity verifies at the issuer, the sign-in or the code, and at the hub, the key; it issues at neither.
- After a restart, the redeemer refuses every key issued before it last started, so no key can be used twice across a restart, at the cost of one more key for a client caught mid-connection; no record of used keys is kept on disk.

**Settled with AGP's review (zorg's `D47`, `D59`).**

- A key is spent once the binding verifies it, even if opening, collision selection or establishment then fails; the client discards it and fetches a fresh key, never assuming whether an interrupted redemption committed.
- A key's lifetime bounds its redemption; establishment is bounded by the hub's deadline from redemption, below, so leaked unused material admits no later than the lifetime, plus the clock tolerance and the largest clock difference accepted - both zero where issuer and redeemer share a process - plus that time-out.
- An explicit refusal from the issuer stops redialling until the proof changes and reaches commands as `admission-refused`; a failure the transport cannot classify is retried under AGP's backoff.
- One redeemer serves one hub audience in one process, which several listeners may share; independently held redemption state for one audience needs a distributed design, outside the first version.
- A key carries the issuing generation - a value the issuer and redeemer choose fresh each time their process starts - and the redeemer accepts only its own generation, so restart refusal compares no monotonic times from two process lifetimes.
- From a key's redemption, one absolute deadline owned by the hub's binding bounds the rest of the handshake, the channel's handoff and AGP's opening, and is handed to AGP as the opening's deadline; an authentication slot that ends on admission, failure or that deadline moves any socket or work still unreleased into a finite retained-resource budget until it is released (AGP's response, `upstream/agp-review-response.md` in zorg).
- A key binds its allowed proof mode, principal, issuer, hub, node and redemption identity in the issuer's and redeemer's trusted state; a pre-shared-key path's public identity is never enough for bearer admission or for a reuse to close a session.
- Under zorg's `D59` (`upstream/agp-reply-isolation-reply.md`), when `admission-key-verifier` accepts a key at the hub, its proved `principal` and `issuer` form the session's immutable `{issuer, principal}` authorization association that `caller-identity` supplies to AGP at admission; across reconnects, the same proxy or browser worker node (`<identity>.<16-hex instance tag>`) dials with a fresh key (`fresh-key-per-dial`) bound to that same `(issuer, principal, hub, node)`, so its replacement channel receives the equal association at admission and can carry pending direct-peer replies without consulting mutable session history.

**Differed, to be settled.**

- How a browser carries a key: at the `wss:` upgrade, in a second protocol value beside AGP's own, or in an exchange inside the protected channel before admission using OAuth's bearer mechanism over SASL (RFC 7628); AGP owns that contract, and the experiments agreed with AGP decide.
- Where the single-use check sits: at AGP's identity-admission port, where the session is known, or in the transport binding, bound to the session afterwards by an exact association; AGP's review prefers the second, conditional on a bounded, incarnation-safe handoff, and the joint lifecycle design decides.
- The request evidence an admitted key gives: caller-identity's `agp-session` record with `proved` `true`, or a new variant naming the issuer.
- The key's format: an opaque handle looked up in memory where the issuer and hub share a process, and an RFC 9068 token where they do not.

---

## Reference

Not yet built.\
This repository, `apnex/credential-issuer`, private until its first working code: `VISION.md` and, once built, the implementation.

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
- `agp`: `peer-identity-evidence`; and, asked, `dialer-credential-source`, `admission-credential`, `session-close`, `preshared-key-resolution`

**Composed-by:** nothing yet.\
Its first consumers, once built, are zorg's hub and command line and zorg's web canvas, and drawv2 when its live channel runs over AGP.

The registry's edge vocabulary has no edge for one component using another's contract without containing it; see the note in operation-call's entry.
