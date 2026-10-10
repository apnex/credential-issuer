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
