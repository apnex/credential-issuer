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

**A credential** means something a client presents on its way to being admitted, of two kinds: a *standing code*, which a signed-in person mints for a machine they provision, under an identity the host's rule lets them hold, and which lasts until it is revoked or reaches an expiry its minter chose; and an *admission key*, which is issued for one connection from one node to one hub.\
A client shows a standing code only to the issuer, never to a hub, and an admission key only to the hub it names; a hub refuses anything else.

**A proof the host accepts** means what a client shows the issuer to be given an admission key: a person's sign-in, which a verifier the host chose checks, or a standing code.\
Whether that proof's principal may have a key for that hub is decided by a rule the host gives the issuer, which the issuer applies and does not write.

**Worth almost nothing once used** means an admission key admits one connection, from the node it names to the hub it names, within about a minute of being issued: whoever presents it first in that minute, claiming that node, is admitted, and every later presentation is refused, its owner's retry included, which is why a fetcher never presents a key twice; and a key is never accepted as proof for another key.\
A bearer copy of a used key admits no one, but presented while the key is live it can still end the session that used the key first, which then reconnects with a fresh key; that disruption is the price of making a stolen key's use visible.

---

## Why it exists

Every service that clients reach directly must decide, when a connection opens, whether to admit it.\
A browser should hold no lasting secret, a command line or an agent must hold one, and each application bridges the two in its own way: a long-lived token the server accepts directly, a code checked on every request, a cookie the page happens to carry.

Each bridge loses something.\
A token the server accepts directly is as good to a thief as to its owner for as long as it lives, a cookie reaches only a server on the page's own site, and a second application builds the same codes, hashes and revocations again.

credential-issuer builds that bridge once: clients prove themselves to an issuer, and every connection is admitted with a key made for it alone, so a hub sees one kind of credential from every client, and keeps nothing a client could present to be admitted later.

---

## What it is

A library whose three parts are embedded in three places, with one duty: issuing the credentials that reach a hub.

- **The issuer**, served by the application, mints and revokes standing codes for signed-in people, and gives admission keys to clients that prove themselves.
- **The redeemer**, embedded in the hub, checks each admission key as the connection is admitted, records its one use, and reports a second use; while the key is live, it names the session that used the key first, for the host to close.
- **The fetcher**, embedded where each client's connection is held, obtains a fresh key before every connection and every reconnection, and keeps none.

The three parts are one duty because they share one key and one rule of single use; split, the key's format and that rule would become a contract between components always used together.\
Its shapes are OAuth 2.0's wherever one fits, so existing libraries can read its keys, and an authorization server an application already runs can stand in for the issuer where it is extended to issue keys for one use.\
The application supplies its verifiers, its rule on who may have a key for which hub, and where the issuer is served; the transport carries the key and, where its profile can, proves possession of it.

---

## What it is not

**Not an identity provider.**\
It signs no one in, creates no accounts, and holds no passwords; it accepts the sign-ins of providers the application trusts.

**Not a verifier of who someone is.**\
It checks only its own credentials; who a person's sign-in says they are is established by the host's verifiers, and the principal of each request by the component that establishes it, so the issuer judges no one's identity and applies the host's rule to a principal it was given.

**Not an authority.**\
It says whether a connection may open, never what a caller may do once it has; which principal may read or change which thing is the application's.

**Not a transport.**\
It protects no channel and frames nothing; the transport carries a key and, where its profile can, proves possession of it.

**Not a renewer of open connections.**\
A key matters when a connection is admitted; afterwards nothing renews or rechecks it, a connection runs until it disconnects, and the one later event a key can still cause is a second use while it is live, after which the host may close the session that used it first.

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
The measure is that no admission key admits a second connection, a leaked key nobody has used admits at most one within its minute, and a standing code - the one lasting secret, kept by the issuer only as a hash and presented only by a machine's own connection holder - stops yielding keys the moment its revocation is recorded.

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
