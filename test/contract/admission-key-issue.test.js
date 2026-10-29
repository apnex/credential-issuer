// admission-key-issue - CONTRACT.md's row, through CIss2, for zorg's D10-E2.
//
// Tests RFC 8693 sign-in and client_credentials standing-code issuance (including minterPrincipal !== identity
// mapping to principal === identity and issuer === minterIssuer, and two authorities with the same principal
// spelling), admission-key-as-proof rejection, isSignInRevoked rechecked at serialized commit, (hub, node) lease
// exclusivity ("node-identity-conflict" on competing (issuer, principal) or missing/wrong continuationSecret,
// "lease-capacity" without live eviction, and maxRetainedKeys capacity), handle-reservation recovery after
// unused-key expiry, explicit unrecorded refusal, terminal redemption and duplicate sweeps, and D54/D55 plain-data
// protection.
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
		set: (ms) => {
			nowMs = ms;
		},
		schedule: () => ({ cancel() {} }),
	};
}

const verifiers = [
	{
		issuer: "authority-a",
		verify(cred) {
			if (cred === "alice-a") return { principal: "alice", session: "sess-a1", expiresAt: 2_000_000 };
			if (cred === "bob-a") return { principal: "bob", session: "sess-b1" };
			return null;
		},
	},
	{
		issuer: "authority-b",
		verify(cred) {
			if (cred === "alice-b") return { principal: "alice", session: "sess-a2" };
			return null;
		},
	},
];

test("CIss2, D10-E2: RFC 8693 sign-in and standing-code issuance, minterPrincipal !== identity mapping, cross-authority same-principal isolation, and admission-key-as-proof rejection", async () => {
	const clock = createTestClock();
	const policySeen = [];
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers,
		clock,
		allowStandingCode: () => true,
		allowAdmissionKey(input) {
			policySeen.push(input);
			return input.principal !== "forbidden";
		},
	});

	// 1) Standing code minted by alice ("authority-a") for identity "buildbot" maps to principal: "buildbot", issuer: "authority-a" (o:F2)
	const minted = await issuer.mintStandingCode({ proof: "alice-a", identity: "buildbot" });
	assert.equal(minted.ok, true);

	const codeKey = await issuer.issueAdmissionKey({
		grantType: "client_credentials",
		clientSecret: minted.code,
		hub: "zorg-hub",
		node: "buildbot.0123456789abcdef",
	});
	assert.equal(codeKey.ok, true);
	assert.equal(codeKey.principal, "buildbot");
	assert.equal(codeKey.issuer, "authority-a");
	assert.equal(codeKey.claims.sub, "buildbot");
	assert.equal(codeKey.claims.iss, "authority-a");
	assert.equal(codeKey.claims.aud, "zorg-hub");
	assert.equal(codeKey.claims.client_id, "buildbot.0123456789abcdef");
	assert.deepEqual(policySeen.at(-1), {
		principal: "buildbot",
		issuer: "authority-a",
		hub: "zorg-hub",
		node: "buildbot.0123456789abcdef",
		proofKind: "standing-code",
		proofMode: "native-tls13-external-psk-v1",
	});

	// Standing code for "buildbot" cannot issue a key for "alice.0123456789abcdef"
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "client_credentials",
			clientSecret: minted.code,
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "proof-refused" },
	);

	// 2) Admission key is never accepted as proof for another admission key or standing code
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: codeKey.bearerToken,
			hub: "zorg-hub",
			node: "buildbot.0123456789abcdef",
			continuationSecret: codeKey.continuationSecret,
		}),
		{ ok: false, code: "proof-refused" },
	);
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "client_credentials",
			clientSecret: codeKey.redemptionId,
			hub: "zorg-hub",
			node: "buildbot.0123456789abcdef",
			continuationSecret: codeKey.continuationSecret,
		}),
		{ ok: false, code: "proof-refused" },
	);

	// 3) Lease exclusivity on (hub, node), including two authorities with the same principal spelling ("alice" under authority-a vs authority-b)
	const aliceKey1 = await issuer.issueAdmissionKey({
		grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
		subjectToken: "alice-a",
		hub: "zorg-hub",
		node: "alice.1111111111111111",
	});
	assert.equal(aliceKey1.ok, true);

	// Renewal with matching continuationSecret and same (issuer, principal) keeps the same instanceBinding
	const aliceKey2 = await issuer.issueAdmissionKey({
		grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
		subjectToken: "alice-a",
		hub: "zorg-hub",
		node: "alice.1111111111111111",
		continuationSecret: aliceKey1.continuationSecret,
	});
	assert.equal(aliceKey2.ok, true);
	assert.equal(aliceKey2.instanceBinding, aliceKey1.instanceBinding);
	assert.notEqual(aliceKey2.redemptionId, aliceKey1.redemptionId);

	// Missing or wrong continuationSecret -> node-identity-conflict
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: "alice-a",
			hub: "zorg-hub",
			node: "alice.1111111111111111",
		}),
		{ ok: false, code: "node-identity-conflict" },
	);
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: "alice-a",
			hub: "zorg-hub",
			node: "alice.1111111111111111",
			continuationSecret: "wrong-secret",
		}),
		{ ok: false, code: "node-identity-conflict" },
	);

	// Same principal spelling "alice" under different authority "authority-b" even with continuationSecret -> node-identity-conflict
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: "alice-b",
			hub: "zorg-hub",
			node: "alice.1111111111111111",
			continuationSecret: aliceKey1.continuationSecret,
		}),
		{ ok: false, code: "node-identity-conflict" },
	);

	// Different principal "bob" claiming active node "alice.1111111111111111" -> node-identity-conflict
	assert.deepEqual(
		await issuer.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: "bob-a",
			hub: "zorg-hub",
			node: "alice.1111111111111111",
			continuationSecret: aliceKey1.continuationSecret,
		}),
		{ ok: false, code: "node-identity-conflict" },
	);
});

test("CIss2, D10-E2: isSignInRevoked rechecked at serialized commit, lease/handle/retained-key capacity without live eviction, and handle-reservation recovery lifecycle", async () => {
	const clock = createTestClock(10_000);
	const revokedSessions = new Set();

	// 1) Sign-in revoked while async allowAdmissionKey is in flight -> caught at serialized commit turn
	const issuerRevokeMidFlight = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers,
		clock,
		isSignInRevoked({ session }) {
			return session !== null && revokedSessions.has(session);
		},
		async allowAdmissionKey() {
			revokedSessions.add("sess-a1");
			return true;
		},
	});
	assert.deepEqual(
		await issuerRevokeMidFlight.issueAdmissionKey({
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			subjectToken: "alice-a",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "proof-refused" },
	);

	// 2) Handle-reservation lifecycle (o:F5): issuance reserves 1 slot; redemption inherits it; unused expiry or terminal compaction releases it at most once
	const capClock = createTestClock(100_000);
	const capIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers,
		clock: capClock,
		keyLifetimeMs: 1_000,
		keyRetentionMs: 5_000,
		reconnectGraceMs: 2_000,
		maxActiveLeases: 2,
		maxHandlesPerLease: 2,
		maxTotalHandles: 3,
		maxRetainedKeys: 10,
	});

	// Lease 1: issue 2 keys (hits maxHandlesPerLease: 2)
	const k1 = await capIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
	});
	const k2 = await capIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
		continuationSecret: k1.continuationSecret,
	});
	assert.equal(k1.ok && k2.ok, true);

	// 3rd key on Lease 1 while k1 and k2 are unspent & live -> refused with lease-capacity
	assert.deepEqual(
		await capIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000001",
			continuationSecret: k1.continuationSecret,
		}),
		{ ok: false, code: "lease-capacity" },
	);

	// Redeem k1: explicit unrecorded refusal ("capacity") keeps k1's 1 reservation without double counting;
	// then recorded redemption inherits k1's 1 reservation without incrementing reservedHandles!
	const arrival1 = {};
	const resolved1 = capIssuer.resolvePsk(k1.pskIdentity, { arrival: arrival1 });
	assert.equal(resolved1.kind, "resolved");

	let redemptionOutcome = { kind: "capacity" };
	let use1State = "established";
	const use1 = {
		lifecycle: { readAdmissionUse: () => ({ state: use1State, sessionId: "s-1" }) },
		control: { requestAdmissionTermination() {} },
		redemption: { recordAdmissionRedemption: () => redemptionOutcome },
	};
	assert.equal(
		capIssuer.completePskProof({ arrival: arrival1, use: use1 }, { arrival: arrival1, lookupRef: resolved1.lookupRef }),
		"refused",
	);
	redemptionOutcome = { kind: "recorded" };
	assert.equal(
		capIssuer.completePskProof({ arrival: arrival1, use: use1 }, { arrival: arrival1, lookupRef: resolved1.lookupRef }),
		"redeemed",
	);

	// Advance clock by 1_000ms (k2 expires unused at 101_000, while k1's slot is still "established"):
	// k2's unused reservation is released on sweep, freeing 1 handle slot on Lease 1!
	capClock.advance(1_000);
	capIssuer.sweepLeases();
	capIssuer.sweepLeases(); // duplicate sweep does not double-decrement!

	const k3 = await capIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
		continuationSecret: k1.continuationSecret,
	});
	assert.equal(k3.ok, true, "unused key k2 expiry released its handle reservation");

	// Now Lease 1 has k1 (established slot) + k3 (unspent live key) = 2 reserved handles -> full again
	assert.deepEqual(
		await capIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000001",
			continuationSecret: k1.continuationSecret,
		}),
		{ ok: false, code: "lease-capacity" },
	);

	// Transition k1's slot to "terminal"; since nowMs (101_000) >= k1.validBeforeMonotonicMs (101_000),
	// sweepLeases compacts k1's terminal slot and releases k1's reservation!
	use1State = "terminal";
	capIssuer.sweepLeases();
	const k4 = await capIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
		continuationSecret: k1.continuationSecret,
	});
	assert.equal(k4.ok, true, "terminal slot compaction released k1's handle reservation");

	// 3) Cross maxActiveLeases (2) and maxRetainedKeys (3) thresholds without live eviction, and test D54/D55 on allowAdmissionKey (F10)
	const leaseCapIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers,
		clock: capClock,
		maxActiveLeases: 2,
		maxHandlesPerLease: 4,
		maxTotalHandles: 10,
		maxRetainedKeys: 3,
	});
	const l1 = await leaseCapIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
	});
	const l2 = await leaseCapIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000002",
	});
	assert.equal(l1.ok && l2.ok, true);
	// 3rd distinct node exceeds maxActiveLeases: 2 -> refused with lease-capacity
	assert.deepEqual(
		await leaseCapIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000003",
		}),
		{ ok: false, code: "lease-capacity" },
	);
	// Issue 3rd key on existing lease l1 -> hits maxRetainedKeys: 3, so 4th key is refused with lease-capacity
	const l1b = await leaseCapIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
		continuationSecret: l1.continuationSecret,
	});
	assert.equal(l1b.ok, true);
	assert.deepEqual(
		await leaseCapIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000001",
			continuationSecret: l1.continuationSecret,
		}),
		{ ok: false, code: "lease-capacity" },
	);

	// D54/D55 on allowAdmissionKey returning non-boolean / nested rejected Promise
	const badPolicyIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers,
		clock: capClock,
		allowAdmissionKey() {
			return { nested: Promise.reject(new Error("D55 policy rejection")) };
		},
	});
	assert.deepEqual(
		await badPolicyIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000001",
		}),
		{ ok: false, code: "policy-refused" },
	);

	// 4) Sign-in proof expiring during sweepLeases() lifecycle observation is refused as proof-refused (Attempt 2 F5)
	for (const endAt of [109, 110, 111]) {
		const sweepExpClock = createTestClock(100);
		let advanceInSweep = false;
		const sweepExpIssuer = createCredentialIssuer({
			hub: "zorg-hub",
			verifiers: [{ issuer: "authority-a", verify: () => ({ principal: "alice", session: "s1", expiresAt: 110 }) }],
			clock: sweepExpClock,
		});
		const firstKey = await sweepExpIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000001",
		});
		const arr = {};
		const look = sweepExpIssuer.resolvePsk(firstKey.pskIdentity, { arrival: arr });
		sweepExpIssuer.completePskProof(
			{
				arrival: arr,
				use: {
					lifecycle: {
						readAdmissionUse() {
							if (advanceInSweep) sweepExpClock.set(endAt);
							return { state: "established", sessionId: "s-1" };
						},
					},
					control: { requestAdmissionTermination() {} },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
				},
			},
			{ arrival: arr, lookupRef: look.lookupRef },
		);
		advanceInSweep = true;
		const secondKey = await sweepExpIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000002",
		});
		if (endAt < 110) {
			assert.equal(secondKey.ok, true);
		} else {
			assert.deepEqual(secondKey, { ok: false, code: "proof-refused" });
		}
	}

	// 5) Sign-in revoked synchronously during sweepLeases() lifecycle polling is rechecked before issuing a key (Attempt 3 F5)
	const f5Clock = createTestClock(100);
	let f5Revoked = false;
	let f5RevokeOnSweep = false;
	const f5Issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [{ issuer: "authority-a", verify: () => ({ principal: "alice", session: "s-f5", expiresAt: 200 }) }],
		clock: f5Clock,
		isSignInRevoked: ({ session }) => session === "s-f5" && f5Revoked,
	});
	const f5First = await f5Issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-a" },
		hub: "zorg-hub",
		node: "alice.0000000000000001",
	});
	const f5Arr = {};
	const f5Look = f5Issuer.resolvePsk(f5First.pskIdentity, { arrival: f5Arr });
	f5Issuer.completePskProof(
		{
			arrival: f5Arr,
			use: {
				lifecycle: {
					readAdmissionUse() {
						if (f5RevokeOnSweep) f5Revoked = true;
						return { state: "established", sessionId: "s-1" };
					},
				},
				control: { requestAdmissionTermination() {} },
				redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
			},
		},
		{ arrival: f5Arr, lookupRef: f5Look.lookupRef },
	);
	f5RevokeOnSweep = true;
	assert.deepEqual(
		await f5Issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-a" },
			hub: "zorg-hub",
			node: "alice.0000000000000002",
		}),
		{ ok: false, code: "proof-refused" },
	);

	// 6) Standing code expiring on wallClock during randomBytes(32) draw in both new-lease and renewal branches is refused as proof-refused (Attempt 5 F1)
	for (const endWall of [1009, 1010, 1011]) {
		for (const isRenewal of [false, true]) {
			const c = createTestClock(100);
			let wall = 1000;
			let advanceOnRandom = false;
			const wc = { nowMs: () => wall };
			const scIssuer = createCredentialIssuer({
				hub: "zorg-hub",
				verifiers,
				clock: c,
				wallClock: wc,
				allowStandingCode: () => true,
				randomBytes(len) {
					if (advanceOnRandom) wall = endWall;
					return new Uint8Array(len).fill(9);
				},
			});
			const sc = await scIssuer.mintStandingCode({
				proof: "alice-a",
				identity: "alice",
				expiresAtMs: 1010,
			});
			assert.equal(sc.ok, true);
			let contSecret;
			if (isRenewal) {
				const firstKey = await scIssuer.issueAdmissionKey({
					grantType: "client_credentials",
					clientSecret: sc.code,
					hub: "zorg-hub",
					node: "alice.0123456789abcdef",
				});
				assert.equal(firstKey.ok, true);
				contSecret = firstKey.continuationSecret;
			}
			advanceOnRandom = true;
			const res = await scIssuer.issueAdmissionKey({
				grantType: "client_credentials",
				clientSecret: sc.code,
				hub: "zorg-hub",
				node: "alice.0123456789abcdef",
				...(contSecret !== undefined ? { continuationSecret: contSecret } : {}),
			});
			if (endWall < 1010) {
				assert.equal(res.ok, true);
			} else {
				assert.deepEqual(res, { ok: false, code: "proof-refused" });
			}
		}
	}
});
