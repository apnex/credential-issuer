// admission-key-verifier - CONTRACT.md's row, through CIss4, for zorg's D10-E2.
//
// Tests dual redemptionId + exact lifecycle object identity verification, EXPECTED_NODE_MISMATCH vs
// SECURITY_EVIDENCE denials, composition with @apnex/caller-identity in "authenticated" mode, and all four
// D62 lease-reclamation conditions (including thrown/malformed readAdmissionUse() retaining the lease and
// close-activity grace anchoring).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createCallerIdentity } from "@apnex/caller-identity";
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
	verify: (cred) => (cred === "alice-token" ? { principal: "alice", session: "s1" } : null),
};

test("CIss4, CI2, CI6, D10-E2: verifyRedeemed dual redemptionId + exact lifecycle verification, composition with caller-identity in authenticated mode, and 4-condition lease reclamation", async () => {
	const clock = createTestClock();
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		keyLifetimeMs: 60_000,
		keyRetentionMs: 120_000,
		reconnectGraceMs: 30_000,
	});

	const callerIdentity = createCallerIdentity({
		mode: "authenticated",
		redeemedVerifier: issuer,
		verifiers: [verifier],
		clock,
	});

	const issued = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(issued.ok, true);

	let lifecycleState = "admitted";
	let throwOnRead = false;
	const lifecycle = {
		readAdmissionUse() {
			if (throwOnRead) throw new Error("readAdmissionUse fault");
			return { state: lifecycleState, sessionId: "s-100" };
		},
	};
	const arrival = {};
	const look = issuer.resolvePsk(issued.pskIdentity, { arrival });
	assert.equal(
		issuer.completePskProof(
			{
				arrival,
				use: {
					lifecycle,
					control: { requestAdmissionTermination() {} },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
				},
			},
			{ arrival, lookupRef: look.lookupRef },
		),
		"redeemed",
	);

	// 1) Exact match on redemptionId, lifecycle object identity, and remoteNodeId -> allowed by caller-identity
	const admissionResult = await callerIdentity.admission.evaluate(
		{
			localNodeId: "zorg-hub",
			remoteNodeId: "alice.0123456789abcdef",
			localSessionId: "000001",
			remoteSessionId: "000002",
			direction: "inbound",
			peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } },
		},
		{
			redeemedAdmission: {
				redemptionId: issued.redemptionId,
				lifecycle,
			},
		},
	);
	assert.deepEqual(admissionResult, {
		decision: "allow",
		authorizationAssociation: {
			mode: "authenticated",
			issuer: "zorg-signin",
			principal: "alice",
			instanceBinding: issued.instanceBinding,
		},
	});
	assert.deepEqual(callerIdentity.sessionPrincipal("alice.0123456789abcdef", "000001"), {
		node: "alice.0123456789abcdef",
		session: "000001",
		principal: "alice",
		proved: true,
	});

	// 2) Cloned lifecycle object (wrong object identity) -> SECURITY_EVIDENCE
	assert.deepEqual(
		issuer.verifyRedeemed({
			redemptionId: issued.redemptionId,
			lifecycle: { ...lifecycle },
			remoteNodeId: "alice.0123456789abcdef",
		}),
		{ ok: false, reasonCode: "SECURITY_EVIDENCE" },
	);

	// 3) Wrong redemptionId -> SECURITY_EVIDENCE
	assert.deepEqual(
		issuer.verifyRedeemed({
			redemptionId: "wrong-id",
			lifecycle,
			remoteNodeId: "alice.0123456789abcdef",
		}),
		{ ok: false, reasonCode: "SECURITY_EVIDENCE" },
	);

	// 4) Mismatched remoteNodeId -> EXPECTED_NODE_MISMATCH
	assert.deepEqual(
		issuer.verifyRedeemed({
			redemptionId: issued.redemptionId,
			lifecycle,
			remoteNodeId: "bob.0123456789abcdef",
		}),
		{ ok: false, reasonCode: "EXPECTED_NODE_MISMATCH" },
	);

	// 5) 4-condition lease reclamation (D62):
	// Advance clock by 70_000ms (past keyLifetimeMs 60_000ms and reconnectGraceMs 30_000ms from issuance),
	// while lifecycle is still "admitted" -> lease is NOT reclaimed
	clock.advance(70_000);
	issuer.sweepLeases();
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "node-identity-conflict" },
	);

	// If readAdmissionUse throws -> treated as unknown (retains lease)
	throwOnRead = true;
	clock.advance(40_000);
	issuer.sweepLeases();
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "node-identity-conflict" },
	);

	// Now readAdmissionUse succeeds and reports { state: "terminal" } at t = +110_000ms:
	// first terminal observation anchors lease.lastActivityMs = +110_000ms, so grace TTL (30_000ms) has not elapsed yet!
	throwOnRead = false;
	lifecycleState = "terminal";
	issuer.sweepLeases();
	clock.advance(29_999);
	issuer.sweepLeases();
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "node-identity-conflict" },
	);

	// Advance 1ms more (+30_000ms since terminal observation): all 4 conditions hold together, lease is reclaimed,
	// and a new issuance for alice.0123456789abcdef without continuationSecret succeeds with a fresh instanceBinding!
	clock.advance(1);
	const reallocated = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(reallocated.ok, true);
	assert.notEqual(reallocated.instanceBinding, issued.instanceBinding);

	// 6) AGP AdmissionUseSnapshot shapes: { state: "established", session: { remoteNodeId, localSessionId, authorizationAssociation } }
	// and { state: "terminal", reachedEstablished: false } / malformed readAdmissionUse shapes (F1, F10)
	const agpSnapClock = createTestClock(2_000_000);
	const agpSnapReports = [];
	const agpSnapIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock: agpSnapClock,
		keyLifetimeMs: 10,
		keyRetentionMs: 100,
		reconnectGraceMs: 5,
		onKeyReuse: (r) => agpSnapReports.push(r),
	});
	const snapKey = await agpSnapIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	let snapObs = {
		state: "established",
		session: {
			remoteNodeId: "alice.0123456789abcdef",
			localSessionId: "agp-session-42",
			authorizationAssociation: {
				mode: "authenticated",
				issuer: "zorg-signin",
				principal: "alice",
				instanceBinding: snapKey.instanceBinding,
			},
		},
	};
	const snapArrival = {};
	const snapLook = agpSnapIssuer.resolvePsk(snapKey.pskIdentity, { arrival: snapArrival });
	const snapUse = {
		lifecycle: { readAdmissionUse: () => snapObs },
		control: { requestAdmissionTermination() {} },
		redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
	};
	assert.equal(
		agpSnapIssuer.completePskProof({ arrival: snapArrival, use: snapUse }, { arrival: snapArrival, lookupRef: snapLook.lookupRef }),
		"redeemed",
	);
	// Second presentation immediately captures firstSession from AGP session.localSessionId ("agp-session-42")
	const snapArr2 = {};
	const snapLook2 = agpSnapIssuer.resolvePsk(snapKey.pskIdentity, { arrival: snapArr2 });
	assert.equal(
		agpSnapIssuer.completePskProof(
			{
				arrival: snapArr2,
				use: {
					lifecycle: { readAdmissionUse: () => ({ state: "pending" }) },
					control: { requestAdmissionTermination() {} },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
				},
			},
			{ arrival: snapArr2, lookupRef: snapLook2.lookupRef },
		),
		"refused",
	);
	assert.equal(agpSnapReports[0].firstSession, "agp-session-42");

	// Malformed readAdmissionUse return (getter, unknown field, reachedEstablished: true without admittedSession,
	// admittedSession: null, or invalid authorizationAssociation) retains the lease (Attempt 2 F1)
	for (const badTerminal of [
		{ state: "terminal", extraField: true },
		{ state: "terminal", reachedEstablished: true },
		{ state: "terminal", reachedEstablished: false, admittedSession: null },
		{
			state: "terminal",
			reachedEstablished: true,
			admittedSession: {
				remoteNodeId: "alice.0123456789abcdef",
				localSessionId: "s-bad",
				authorizationAssociation: 42,
			},
		},
	]) {
		snapObs = badTerminal;
		agpSnapClock.advance(20);
		agpSnapIssuer.sweepLeases();
		assert.deepEqual(
			await agpSnapIssuer.issueAdmissionKey({
				proof: { kind: "sign-in", token: "alice-token" },
				hub: "zorg-hub",
				node: "alice.0123456789abcdef",
			}),
			{ ok: false, code: "node-identity-conflict" },
		);
	}

	// Valid AGP { state: "terminal", reachedEstablished: false } reclaims the lease after grace (5ms)
	snapObs = { state: "terminal", reachedEstablished: false };
	agpSnapIssuer.sweepLeases();
	agpSnapClock.advance(5);
	agpSnapIssuer.sweepLeases();
	const afterAgpTerminal = await agpSnapIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(afterAgpTerminal.ok, true);
});
