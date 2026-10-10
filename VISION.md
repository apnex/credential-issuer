# credential-issuer - Vision

**Status: drafted 2026-10-10 under zorg's `D35`, `D38` and `D39`; not ratified.**\
This document states why credential-issuer exists and what it will never be.\
It carries no current state, no roadmap, and no schedule.

Holding this document authorises nothing.\
It does not ratify a decision, admit a component to any registry, or approve a contract change.\
Until the director ratifies it, it is a proposal, and nothing may cite it as enduring.\
A change of direction is recorded as a decision first and absorbed here afterwards.

---

## North star

> Let every connection to a hub be admitted with a credential that is worth almost nothing once used - issued for that one connection, from a proof the host accepts - so that no client ever presents a hub with anything it would accept twice.

Four terms in that sentence carry weight, so this document defines them rather than leaving them to the reader; a *hub* is a service that many clients connect to directly, and a *client* is a browser page, a command line or an agent reaching it.

**A connection** means one session a client opens to a hub and keeps until it disconnects: the hub admits it once, when it opens, and not again for each request it carries.

**A credential** means something a client presents to be admitted, of two kinds: a *standing code*, which a signed-in person mints for a machine and which lasts until it is revoked, and an *admission key*, which is issued for one connection.\
A standing code is shown only to the issuer, never to a hub; an admission key is shown only to the hub it names.

**A proof the host accepts** means what a client shows the issuer to be given an admission key: a person's sign-in, which a verifier the host chose checks, or a standing code.\
Whether that proof's principal may have a key for that hub is the host's rule, not the issuer's.

**Worth almost nothing once used** means an admission key admits one connection, to one hub, within about a minute of being issued; a copy is refused once the key has been used, and a key is never accepted as proof for another key.

---

## Why it exists

Every service that clients reach directly must decide, when a connection opens, whether to admit it.\
A browser should hold no lasting secret, a command line or an agent must hold one, and each application bridges the two in its own way: a long-lived token the server accepts directly, a code checked on every request, a cookie the page happens to carry.

Each bridge loses something.\
A token the server accepts directly is as good to a thief as to its owner for as long as it lives, a cookie reaches only a server on the page's own site, and a second application builds the same codes, hashes and revocations again.

credential-issuer builds that bridge once: clients prove themselves to an issuer, and every connection is admitted with a key made for it alone, so a hub sees one kind of credential from every client, and holds nothing that could admit anyone later.

---

## What it is

An embeddable library in three parts, one duty: issuing the credentials that reach a hub.

- **The issuer**, served by the application, mints and revokes standing codes for signed-in people, and gives admission keys to clients that prove themselves.
- **The redeemer**, embedded in the hub, checks each admission key as the connection is admitted, records its one use, and reports a second use, naming the session that used the key first for the hub to close.
- **The fetcher**, embedded where each client's connection is held, obtains a fresh key before every connection and every reconnection, and keeps none.

Its shapes are OAuth 2.0's wherever one fits, so an application that already runs an authorization server can stand in for the issuer.\
The application supplies its verifiers, its rule on who may have a key for which hub, and where the issuer is served; the transport carries the key and proves it.

---

## What it is not

**Not an identity provider.**\
It signs no one in, creates no accounts, and holds no passwords; it accepts the sign-ins of providers the application trusts.

**Not a verifier of who someone is.**\
Who a sign-in or a key says is calling is established by the host's verifiers, through the component that establishes each request's principal; the issuer stamps a principal it was given, and decides nothing about it.

**Not an authority.**\
It says whether a connection may open, never what a caller may do once it has; which principal may read or change which thing is the application's.

**Not a transport.**\
It protects no channel and frames nothing; the transport carries a key and, where its profile can, proves possession of it.

**Not a renewer of open connections.**\
A key matters when a connection is admitted and never afterwards; a connection runs until it disconnects.

**Not an authorization server for every purpose.**\
It borrows OAuth's shapes where they serve its one duty, and offers no consent screens, delegated grants or tokens for other services.

**Not agentic.**\
It admits the connections of agentic systems and contains no cognition, model, or orchestration.

---

## What success means

Four dimensions.\
They are not weighted, and they do not collapse.

**Exposure.**\
Nothing a hub accepts is worth stealing twice.\
The measure is that no admission key admits a second connection, a leaked key admits at most one within its minute, and a standing code - the one lasting secret, held only by a machine's own connection holder - stops yielding keys the moment it is revoked.

**Unity.**\
Every client reaches a hub the same way.\
The measure is one kind of credential at the hub, one admission check, and one place where proofs are judged, whatever the client and whatever the path.

**Leanness.**\
An application adds little code to admit its clients.\
The measure is the code an application writes beyond its verifiers, its rule and its issuing route, stated and small, with no shape of its own where OAuth's serves.

**Reuse.**\
A second, unrelated application adopts it without a variant, a fork, or a privileged path.

A programme strong on three of these and weak on one has one unmet dimension, and which one it is says more than any average of the four.

---

## Authority

Held by the director.\
Drafted by anyone; ratified only by the director.

This statement is amended, never quietly rewritten.\
A ruling that changes direction is recorded as a decision and absorbed here, so the reasoning survives the change.

Where this narrative and a verified record disagree about state, the record governs.
