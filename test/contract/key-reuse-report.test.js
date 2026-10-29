// key-reuse-report - CONTRACT.md's row, through CIss3, for zorg's D10-E2.
//
// Tests that each refused second use is reported once to onKeyReuse with keyFingerprint, principal, issuer,
// hub, node, distinct firstUseId/secondUseId, and firstSession/secondSession (including after terminal slot
// compaction and lease reclamation via preserved firstUseSummary), never exposing the raw key, its 32-byte
// secret, or the primary proof that obtained it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createCredentialIssuer } from "@apnex/credential-issuer";

function createTestClock(initialMs = 1_000_000) {
	let nowMs = initialMs;
	return {
		now: () => nowMs,
		advance: (ms) => {
			nowMs += ms;
		},
		schedule: () => ({ cancel() {} }),
	};
}

const verifier = {
	issuer: "zorg-signin",
	verify: (cred) => (cred === "super-secret-signin-token" ? { principal: "alice", session: "s1" } : null),
};

test("CIss3, D10-E2: KeyReuseReport carries distinct firstUseId/secondUseId and session identities, survives terminal slot compaction and lease reclamation within keyRetentionMs, and never leaks secrets", async () => {
	const clock = createTestClock();
	const reports = [];
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		keyLifetimeMs: 60_000,
		keyRetentionMs: 120_000,
		reconnectGraceMs: 10_000,
		onKeyReuse(r) {
			reports.push(r);
		},
	});

	const issued = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "super-secret-signin-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(issued.ok, true);

	// Redeem first use; session transitions from established ("session-alpha") to terminal
	let use1State = "established";
	let terminated = 0;
	const arrival1 = {};
	const look1 = issuer.resolvePsk(issued.pskIdentity, { arrival: arrival1 });
	const use1 = {
		lifecycle: { readAdmissionUse: () => ({ state: use1State, sessionId: "session-alpha" }) },
		control: { requestAdmissionTermination: () => { terminated += 1; } },
		redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
	};
	assert.equal(
		issuer.completePskProof({ arrival: arrival1, use: use1 }, { arrival: arrival1, lookupRef: look1.lookupRef }),
		"redeemed",
	);

	// Sweep while established so sessionId "session-alpha" is observed
	issuer.sweepLeases();

	// Second presentation while live (at +10s < 60s): stops first session and reports with firstSession: "session-alpha"
	clock.advance(10_000);
	const arrival2 = {};
	const look2 = issuer.resolvePsk(issued.pskIdentity, { arrival: arrival2 });
	const use2 = {
		lifecycle: { readAdmissionUse: () => ({ state: "pending" }) },
		control: { requestAdmissionTermination() {} },
		redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
	};
	assert.equal(
		issuer.completePskProof({ arrival: arrival2, use: use2 }, { arrival: arrival2, lookupRef: look2.lookupRef }),
		"refused",
	);
	assert.equal(terminated, 1);
	assert.equal(reports.length, 1);
	const r1 = reports[0];
	assert.ok(Object.isFrozen(r1));
	assert.equal(r1.principal, "alice");
	assert.equal(r1.issuer, "zorg-signin");
	assert.equal(r1.hub, "zorg-hub");
	assert.equal(r1.node, "alice.0123456789abcdef");
	assert.equal(r1.firstSession, "session-alpha");
	assert.equal(r1.secondSession, null);
	assert.equal(r1.firstSessionStopped, true);
	assert.notEqual(r1.firstUseId, r1.secondUseId);

	// Now transition use1 to terminal, advance clock past keyLifetimeMs (+60_000ms total = 70_000ms) and reconnectGraceMs,
	// and run sweepLeases() so the terminal slot is compacted and the lease is reclaimed, while key is still within keyRetentionMs (120_000ms) (o:F3, o:F6)
	use1State = "terminal";
	clock.advance(50_000); // now at +60s: validBeforeMonotonicMs reached, terminalObservedAtMs recorded
	issuer.sweepLeases();
	clock.advance(15_000); // now at +75s: reconnectGraceMs (10s) elapsed, lease reclaimed!
	issuer.sweepLeases();

	const arrival3 = {};
	const look3 = issuer.resolvePsk(issued.pskIdentity, { arrival: arrival3 });
	assert.equal(look3.kind, "resolved", "still within 120s keyRetentionMs");
	const use3 = {
		lifecycle: { readAdmissionUse: () => ({ state: "pending" }) },
		control: { requestAdmissionTermination() {} },
		redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
	};
	assert.equal(
		issuer.completePskProof({ arrival: arrival3, use: use3 }, { arrival: arrival3, lookupRef: look3.lookupRef }),
		"refused",
	);
	assert.equal(terminated, 1, "no further termination call after expiry/compaction");
	assert.equal(reports.length, 2);
	const r2 = reports[1];
	assert.equal(r2.firstUseId, r1.firstUseId, "firstUseId preserved in firstUseSummary after slot compaction");
	assert.equal(r2.firstSession, "session-alpha", "firstSession preserved in firstUseSummary after slot compaction");
	assert.equal(r2.secondSession, null);
	assert.equal(r2.firstSessionStopped, false);
	assert.notEqual(r2.secondUseId, r1.secondUseId);

	// Verify no secret or primary proof appears anywhere in the serialized reports
	const serialized = JSON.stringify(reports);
	assert.equal(serialized.includes(issued.secretHex), false);
	assert.equal(serialized.includes(issued.bearerToken), false);
	assert.equal(serialized.includes("super-secret-signin-token"), false);
});
