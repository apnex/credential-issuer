// fresh-key-per-dial - CONTRACT.md's row, through CIss5, for zorg's D10-E2.
//
// Tests direct composition of issuer.issueAdmissionKey with createCredentialPresenterTarget, fresh key per dial
// and reconnect with continuationSecret, issuer-to-presenter secretHex / Uint8Array(32) boundary validation and
// malformed-secret refusal, standing code presented only to the issuer, explicit classification of "lease-capacity",
// "code-store-unwritable", network failure, expired key, malformed key and thrown/rejected issueKey as
// "issuer-unavailable" vs explicit current policy/proof refusal as "issuer-refused" (with nothing dialled),
// constructor throw leaving permit.releaseUnused() to the caller, all three dispose() permit-custody cases, and
// observeAdjacencyRefusal subscribe-before-read ordering, "issuer-refused" vs "issuer-unavailable" mapping, and
// generation >= receipt.generation rearming.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
	createCredentialIssuer,
	createCredentialPresenterTarget,
	observeAdjacencyRefusal,
} from "@apnex/credential-issuer";

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

test("CIss5, A3, D10-E2: createCredentialPresenterTarget composes with issuer.issueAdmissionKey, fetches a fresh key per dial with continuationSecret, presents standing codes only to issueKey, and enforces constructor throw + 3-case dispose() permit custody", async () => {
	const clock = createTestClock();
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
	});
	const mintedCode = await issuer.mintStandingCode({ proof: "alice-token", identity: "alice" });
	assert.equal(mintedCode.ok, true);

	let currentProof = { kind: "standing-code", code: mintedCode.code };
	const seenIssueReqs = [];
	const seenConnectKeys = [];
	let transferredSocketClosed = 0;

	const presenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => currentProof,
		issueKey: (req) => {
			seenIssueReqs.push(req);
			return issuer.issueAdmissionKey(req);
		},
		connectWithKey: async (key) => {
			seenConnectKeys.push(key);
			return {
				channel: { id: key.redemptionId },
				socket: {
					close() {
						transferredSocketClosed += 1;
					},
				},
				transferred: true,
			};
		},
	});

	// 1) Constructor throw leaves permit.releaseUnused() uncalled and accessible to caller (A3)
	let badPermitReleased = 0;
	const badPermit = { releaseUnused() { badPermitReleased += 1; } };
	const savedProof = currentProof;
	currentProof = null;
	assert.throws(() => presenter.createCredentialAttempt(undefined, badPermit), TypeError);
	assert.equal(badPermitReleased, 0, "constructor throw does not consume permit");
	badPermit.releaseUnused();
	assert.equal(badPermitReleased, 1);
	currentProof = savedProof;

	// 2) First dial: fetches fresh key1, stores continuationSecret, presents key1 to connectWithKey (standing code never reaches connectWithKey),
	// and Case 3 (transferred channel): dispose() never calls permit.releaseUnused()
	let permit1Released = 0;
	const attempt1 = presenter.createCredentialAttempt(undefined, { releaseUnused() { permit1Released += 1; } });
	const prep1 = await attempt1.prepareCredential();
	assert.equal(prep1.kind, "prepared");
	assert.ok(presenter.getContinuationSecret()?.startsWith("ci_cont_"));
	await prep1.connection.connect();
	// Calling connect() a second time on the same attempt is rejected
	await assert.rejects(() => prep1.connection.connect());
	await attempt1.dispose();
	await attempt1.dispose(); // idempotent
	assert.equal(permit1Released, 0, "Case 3 (transferred channel) never releases or refunds active permit");
	assert.equal(transferredSocketClosed, 0, "Case 3 (transferred channel) never closes the transferred socket/channel");

	// Standing code was sent only to issueKey, never to connectWithKey
	assert.equal(seenIssueReqs[0].clientSecret, mintedCode.code);
	assert.equal(JSON.stringify(seenConnectKeys[0]).includes(mintedCode.code), false);
	assert.equal(seenConnectKeys[0].secret.byteLength, 32);

	// 3) Reconnect dial: automatically passes stored continuationSecret, keeps same instanceBinding, and fetches a fresh key2
	let permit2Released = 0;
	const attempt2 = presenter.createCredentialAttempt(undefined, { releaseUnused() { permit2Released += 1; } });
	const prep2 = await attempt2.prepareCredential();
	assert.equal(prep2.kind, "prepared");
	assert.equal(prep2.keyMeta.instanceBinding, prep1.keyMeta.instanceBinding);
	assert.notEqual(prep2.keyMeta.redemptionId, prep1.keyMeta.redemptionId);
	assert.equal(seenIssueReqs[1].continuationSecret, presenter.getContinuationSecret());

	// Case 1 (no socket created): dispose() before connect() releases permit once after prepare settled
	await attempt2.dispose();
	assert.equal(permit2Released, 1, "Case 1 (no socket created) releases permit once");

	// 4) Case 2 (untransferred socket created): dispose() waits for socket.closed before releasing permit
	let closeSocket;
	let socketClosedResolved = false;
	const socketClosedPromise = new Promise((r) => {
		closeSocket = () => {
			socketClosedResolved = true;
			r();
		};
	});
	let permit3Released = 0;
	let socketCloseCalled = 0;
	const presenterCase2 = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => currentProof,
		issueKey: (req) => issuer.issueAdmissionKey(req),
		connectWithKey: async () => ({
			socket: {
				closed: socketClosedPromise,
				close() {
					socketCloseCalled += 1;
				},
			},
			transferred: false,
		}),
	});
	presenterCase2.setContinuationSecret(presenter.getContinuationSecret());
	const attempt3 = presenterCase2.createCredentialAttempt(undefined, { releaseUnused() { permit3Released += 1; } });
	const prep3 = await attempt3.prepareCredential();
	assert.equal(prep3.kind, "prepared");
	await prep3.connection.connect();
	const disp3 = attempt3.dispose();
	await new Promise((r) => setImmediate(r));
	assert.equal(socketCloseCalled, 1);
	assert.equal(permit3Released, 0, "Case 2 waits for exact native socket close before releasing permit");
	closeSocket();
	await disp3;
	assert.equal(socketClosedResolved, true);
	assert.equal(permit3Released, 1, "Case 2 releases permit after socket.closed resolves");
});

test("CIss5, A3, A4, D10-E2: classification of issuer-unavailable vs issuer-refused (with nothing dialled), plain-JSON secretHex boundary validation, and observeAdjacencyRefusal subscribe-before-read and generation >= receipt.generation rearming", async () => {
	const clock = createTestClock();
	let dialCount = 0;
	let currentResponse = { ok: false, code: "lease-capacity" };

	const presenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => ({ kind: "sign-in", token: "alice-token" }),
		issueKey: () => {
			if (typeof currentResponse === "function") return currentResponse();
			return currentResponse;
		},
		connectWithKey: async () => {
			dialCount += 1;
			return {};
		},
	});

	// 1) Retryable / malformed / capacity / expired failures classify as "issuer-unavailable" (o:F1, o:F7)
	const unavailableCases = [
		{ ok: false, code: "lease-capacity" },
		{ ok: false, code: "code-store-unwritable" },
		() => {
			throw new Error("network error");
		},
		() => Promise.reject(new Error("async network error")),
		null,
		"not-an-object",
		// Expired key at arrival
		{
			ok: true,
			redemptionId: "g1-1",
			pskIdentity: "g1-1",
			secretHex: "aa".repeat(32),
			bearerToken: "ci_key_g1-1",
			proofMode: "native-tls13-external-psk-v1",
			issuer: "zorg-signin",
			principal: "alice",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			instanceBinding: "g1-1",
			continuationSecret: "ci_cont_1",
			validBeforeMonotonicMs: clock.now(),
		},
		// Malformed secretHex (not 64 hex chars)
		{
			ok: true,
			redemptionId: "g1-1",
			pskIdentity: "g1-1",
			secretHex: "not-hex",
			bearerToken: "ci_key_g1-1",
			proofMode: "native-tls13-external-psk-v1",
			issuer: "zorg-signin",
			principal: "alice",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			instanceBinding: "g1-1",
			continuationSecret: "ci_cont_1",
			validBeforeMonotonicMs: clock.now() + 60_000,
		},
		// Mismatched Uint8Array secret vs secretHex
		{
			ok: true,
			redemptionId: "g1-1",
			pskIdentity: "g1-1",
			secret: new Uint8Array(32).fill(1),
			secretHex: "ff".repeat(32),
			bearerToken: "ci_key_g1-1",
			proofMode: "native-tls13-external-psk-v1",
			issuer: "zorg-signin",
			principal: "alice",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			instanceBinding: "g1-1",
			continuationSecret: "ci_cont_1",
			validBeforeMonotonicMs: clock.now() + 60_000,
		},
	];

	for (const c of unavailableCases) {
		currentResponse = c;
		const attempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
		const res = await attempt.prepareCredential();
		assert.equal(res.kind, "issuer-unavailable");
		await attempt.dispose();
	}

	// Plain-JSON wire response carrying only secretHex (without Uint8Array secret) is decoded into a 32-byte Uint8Array (o:F1)
	currentResponse = {
		ok: true,
		redemptionId: "g1-99",
		pskIdentity: "g1-99",
		secretHex: "ab".repeat(32),
		bearerToken: "ci_key_g1-99",
		proofMode: "native-tls13-external-psk-v1",
		issuer: "zorg-signin",
		principal: "alice",
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		instanceBinding: "g1-1",
		continuationSecret: "ci_cont_1",
		validBeforeMonotonicMs: clock.now() + 60_000,
	};
	const attemptPlainJson = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	const prepPlainJson = await attemptPlainJson.prepareCredential();
	assert.equal(prepPlainJson.kind, "prepared");
	await attemptPlainJson.dispose();

	// 2) Explicit current refusal codes classify as "issuer-refused" with nothing dialled
	for (const code of ["proof-refused", "policy-refused", "node-identity-conflict"]) {
		currentResponse = { ok: false, code };
		const attempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
		const res = await attempt.prepareCredential();
		assert.deepEqual(res, { kind: "issuer-refused", code });
		await attempt.dispose();
	}
	assert.equal(dialCount, 0, "nothing dialled on any issuer-unavailable or issuer-refused outcome");

	// 3) observeAdjacencyRefusal (A4): subscribes to events() BEFORE initial readAdjacencies(), maps only
	// current "issuer-refused" (never "issuer-unavailable") to "admission-refused", and rearms at generation >= receipt.generation
	const callOrder = [];
	const listeners = [];
	let currentSnap = {
		adjacencyId: "adj-1",
		adopted: false,
		credential: { phase: "issuer-unavailable", generation: 1 },
	};
	const refusedNotifications = [];
	const installedProofs = [];

	const observer = observeAdjacencyRefusal({
		adjacencyId: "adj-1",
		events() {
			callOrder.push("events-subscribed");
			return {
				subscribe(fn) {
					listeners.push(fn);
					return { unsubscribe() {} };
				},
			};
		},
		readAdjacencies() {
			callOrder.push("readAdjacencies");
			return { items: [currentSnap] };
		},
		installProof(p) {
			callOrder.push("installProof");
			installedProofs.push(p);
		},
		async notifyCredentialChange() {
			callOrder.push("notifyCredentialChange");
			// Simulate AGP advancing generation to 4 ("prepared") before receipt resolves
			currentSnap = {
				adjacencyId: "adj-1",
				adopted: false,
				credential: { phase: "prepared", generation: 4 },
			};
			return { kind: "committed", generation: 3 };
		},
		onAdmissionRefused(info) {
			refusedNotifications.push(info);
		},
	});

	assert.deepEqual(callOrder.slice(0, 2), ["events-subscribed", "readAdjacencies"], "subscribes before initial read");
	assert.equal(observer.getStatus().admissionRefused, false, "issuer-unavailable never maps to admission-refused");
	assert.equal(observer.getStatus().proxyCode, null);

	// Transition to issuer-refused at generation 2
	currentSnap = {
		adjacencyId: "adj-1",
		adopted: false,
		credential: { phase: "issuer-refused", generation: 2, code: "proof-refused" },
	};
	listeners[0]({ type: "adjacency.credential-changed", adjacencyId: "adj-1" });
	assert.deepEqual(observer.getStatus(), {
		admissionRefused: true,
		proxyCode: "admission-refused",
		phase: "issuer-refused",
		generation: 2,
		code: "proof-refused",
	});
	assert.equal(refusedNotifications.length, 1);

	// Rearm with new proof: installProof runs BEFORE notifyCredentialChange, and snapshot generation 4 >= receipt generation 3 is accepted
	const rearmed = await observer.updateProofAndRearm("fresh-signin-token");
	assert.equal(installedProofs[0], "fresh-signin-token");
	const installIdx = callOrder.indexOf("installProof");
	const notifyIdx = callOrder.indexOf("notifyCredentialChange");
	assert.ok(installIdx >= 0 && installIdx < notifyIdx, "installProof runs before notifyCredentialChange");
	assert.equal(rearmed.kind, "committed");
	assert.equal(rearmed.generation, 4);
	assert.equal(rearmed.status.admissionRefused, false);
	assert.equal(rearmed.status.proxyCode, null);

	// Stale snapshot from generation 2 (< 4) cannot restore the old refusal
	currentSnap = {
		adjacencyId: "adj-1",
		adopted: false,
		credential: { phase: "issuer-refused", generation: 2, code: "proof-refused" },
	};
	observer.refresh();
	assert.equal(observer.getStatus().admissionRefused, false);
	assert.equal(observer.getStatus().generation, 4);

	observer.stop();
});
