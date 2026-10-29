// preshared-key-secret - CONTRACT.md's row, through CIss2 and CIss3, for zorg's D10-E2.
//
// Tests 32-byte cryptographically random Uint8Array secret + secretHex from randomBytes(32), <= 127-byte
// printable ASCII pskIdentity, non-consuming resolvePsk (retaining spent/expired keys within keyRetentionMs
// without spending an unspent key or reporting reuse at lookup time), and lookupRef reuse within an attempt.
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
	verify: (cred) => (cred === "alice-token" ? { principal: "alice", session: "s1" } : null),
};

test("CIss2, CIss3, A1, A2, D10-E2: 32-byte randomBytes(32) PSK secret, printable ASCII pskIdentity <= maxPskIdentityBytes, and non-consuming resolvePsk across unspent, spent and expired-within-retention keys", async () => {
	const clock = createTestClock();
	const randomCalls = [];
	let seed = 1;
	const customRandomBytes = (len) => {
		randomCalls.push(len);
		const out = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			out[i] = (seed * 37 + i * 13) & 0xff;
		}
		seed += 1;
		return out;
	};

	const reuseReports = [];
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		randomBytes: customRandomBytes,
		keyLifetimeMs: 60_000,
		keyRetentionMs: 120_000,
		onKeyReuse: (r) => reuseReports.push(r),
	});

	const issued = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(issued.ok, true);
	assert.ok(issued.secret instanceof Uint8Array);
	assert.equal(issued.secret.byteLength, 32);
	assert.match(issued.secretHex, /^[0-9a-f]{64}$/);
	assert.equal(Buffer.from(issued.secret).toString("hex"), issued.secretHex);
	assert.ok(randomCalls.includes(32), "32-byte secret drawn from randomBytes(32)");
	assert.ok(issued.pskIdentity.length >= 1 && issued.pskIdentity.length <= 127);
	assert.match(issued.pskIdentity, /^[\x21-\x7e]+$/);

	// 1) Seeing a key's pskIdentity in resolvePsk never spends the key, never reports reuse, and returns a defensive Uint8Array copy
	const arrival1 = {};
	const look1 = issuer.resolvePsk(issued.pskIdentity, { arrival: arrival1 });
	assert.equal(look1.kind, "resolved");
	assert.deepEqual(look1.secret, issued.secret);
	look1.secret.fill(0xff); // mutating returned copy does not mutate stored secret

	const look2 = issuer.resolvePsk(issued.pskIdentity, { arrival: arrival1 });
	assert.equal(look2.kind, "resolved");
	assert.deepEqual(look2.secret, issued.secret);
	assert.equal(look2.lookupRef, look1.lookupRef, "same attempt reuses lookupRef");

	// Selector-only probes from other arrivals never spend the key or emit onKeyReuse
	for (let i = 0; i < 5; i++) {
		const probe = issuer.resolvePsk(issued.pskIdentity, { arrival: {} });
		assert.equal(probe.kind, "resolved");
	}
	assert.equal(reuseReports.length, 0, "selector-only resolvePsk never reports reuse");

	// 2) Legitimate presenter still redeems the key after selector-only lookups
	let terminated = 0;
	const use1 = {
		lifecycle: { readAdmissionUse: () => ({ state: "established", sessionId: "sess-live-1" }) },
		control: { requestAdmissionTermination: () => { terminated += 1; } },
		redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
	};
	assert.equal(
		issuer.completePskProof({ arrival: arrival1, use: use1 }, { arrival: arrival1, lookupRef: look1.lookupRef }),
		"redeemed",
	);
	assert.equal(terminated, 0);
	assert.equal(reuseReports.length, 0);

	// 3) While spent and even after keyLifetimeMs (60_000) within keyRetentionMs (120_000), resolvePsk still returns
	// the secret without reporting at lookup time, and returns "unknown" once keyRetentionMs has passed
	clock.advance(70_000); // now at +70s: past validBeforeMonotonicMs (60s), inside retainUntilMonotonicMs (120s)
	const lookAfterExpiry = issuer.resolvePsk(issued.pskIdentity, { arrival: {} });
	assert.equal(lookAfterExpiry.kind, "resolved");
	assert.equal(reuseReports.length, 0, "lookup alone after expiry still does not report reuse");

	clock.advance(50_000); // now at +120s: at retainUntilMonotonicMs
	assert.deepEqual(issuer.resolvePsk(issued.pskIdentity, { arrival: {} }), { kind: "unknown" });

	// Invalid / non-ASCII / overlong pskIdentity returns { kind: "unknown" }
	for (const badId of ["", "has space", "has\u0000nul", "x".repeat(128), "🙂"]) {
		assert.deepEqual(issuer.resolvePsk(badId), { kind: "unknown" });
	}

	// If maxPskIdentityBytes is configured smaller than the generated redemptionId, issueAdmissionKey refuses with incompatible-psk-identity
	const tinyIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		maxPskIdentityBytes: 5,
	});
	assert.deepEqual(
		await tinyIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "incompatible-psk-identity" },
	);
});
