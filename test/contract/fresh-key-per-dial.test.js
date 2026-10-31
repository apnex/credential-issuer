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
import { readPlainJson } from "@apnex/shape-check";

/** Wraps `target` in a Proxy that counts `getOwnPropertyDescriptor` per key into `counts`, throwing for `throwOn`. */
function countingProxy(target, counts, throwOn) {
	return new Proxy(target, {
		getOwnPropertyDescriptor(t, p) {
			counts[p] = (counts[p] ?? 0) + 1;
			if (p === throwOn) throw new Error(`descriptor read of ${String(p)} throws`);
			return Reflect.getOwnPropertyDescriptor(t, p);
		},
	});
}

/** A token object that `readPlainJson` refuses because it carries an accessor property. */
function tokenWithGetter() {
	return Object.defineProperty({ sub: "alice" }, "role", { get: () => "admin", enumerable: true });
}

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

	// 5) Case 2 without native close receipt (socket.closed missing) never refunds permit early (F7)
	let permitNoReceiptReleased = 0;
	let noReceiptCloseCalled = 0;
	const presenterNoReceipt = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => currentProof,
		issueKey: (req) => issuer.issueAdmissionKey(req),
		connectWithKey: async () => ({
			socket: {
				close() {
					noReceiptCloseCalled += 1;
				},
			},
			transferred: false,
		}),
	});
	presenterNoReceipt.setContinuationSecret(presenter.getContinuationSecret());
	const attemptNoReceipt = presenterNoReceipt.createCredentialAttempt(undefined, {
		releaseUnused() {
			permitNoReceiptReleased += 1;
		},
	});
	const prepNoReceipt = await attemptNoReceipt.prepareCredential();
	assert.equal(prepNoReceipt.kind, "prepared");
	await prepNoReceipt.connection.connect();
	await attemptNoReceipt.dispose();
	assert.equal(noReceiptCloseCalled, 1);
	assert.equal(permitNoReceiptReleased, 0, "without exact native-close receipt, permit is never refunded early");

	// 6) Deep immutable primary-proof snapshot: mutating a sign-in token object after createCredentialAttempt does not change what prepareCredential sends (F6)
	const mutableToken = { assertion: "original" };
	let seenTokenAssertion = null;
	const presenterDeepSnap = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => ({ kind: "sign-in", token: mutableToken }),
		issueKey(req) {
			seenTokenAssertion = req.subjectToken.assertion;
			return { ok: false, code: "proof-refused" };
		},
		connectWithKey: async () => ({}),
	});
	const attemptDeepSnap = presenterDeepSnap.createCredentialAttempt(undefined, { releaseUnused() {} });
	mutableToken.assertion = "mutated";
	const resDeepSnap = await attemptDeepSnap.prepareCredential();
	await attemptDeepSnap.dispose();
	assert.equal(seenTokenAssertion, "original", "captured sign-in token snapshot is deeply immutable");
	assert.equal(resDeepSnap.kind, "issuer-unavailable", "mutated current proof supersedes the captured proof");

	// 7) Reentrant attempt.dispose() inside issueKey waits for issueKey's Promise to settle before releasing permit (Attempt 2 F2),
	// single-read createdSocket.closed accessor is captured once (Attempt 2 F3), getProof() throws/extra rejected Promises are observed (Attempt 2 F4),
	// and issueKey response reflection advancing clock to >= validBeforeMonotonicMs returns issuer-unavailable (Attempt 2 F7)
	let reentrantReleased = 0;
	let resolvePendingIssue;
	let currentAttempt;
	const reentrantPresenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => ({ kind: "sign-in", token: "alice-token" }),
		issueKey() {
			void currentAttempt.dispose();
			return new Promise((r) => {
				resolvePendingIssue = () => r({ ok: false, code: "proof-refused" });
			});
		},
		connectWithKey: async () => ({}),
	});
	currentAttempt = reentrantPresenter.createCredentialAttempt(undefined, {
		releaseUnused() {
			reentrantReleased += 1;
		},
	});
	const reentrantPrep = currentAttempt.prepareCredential();
	await new Promise((r) => setImmediate(r));
	assert.equal(reentrantReleased, 0, "reentrant dispose inside issueKey must wait until issueKey settles");
	resolvePendingIssue();
	await reentrantPrep;
	await currentAttempt.dispose();
	assert.equal(reentrantReleased, 1);

	// Single-read createdSocket.closed accessor (Attempt 2 F3)
	let f3Released = 0;
	let f3ClosedReads = 0;
	let resolveF3Close;
	const f3ClosePromise = new Promise((r) => {
		resolveF3Close = r;
	});
	const f3Presenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => currentProof,
		issueKey: (req) => issuer.issueAdmissionKey(req),
		connectWithKey: async () => ({
			socket: {
				close() {},
				get closed() {
					f3ClosedReads += 1;
					return f3ClosedReads === 1 ? f3ClosePromise : undefined;
				},
			},
			transferred: false,
		}),
	});
	f3Presenter.setContinuationSecret(presenter.getContinuationSecret());
	const f3Attempt = f3Presenter.createCredentialAttempt(undefined, {
		releaseUnused() {
			f3Released += 1;
		},
	});
	const f3Prep = await f3Attempt.prepareCredential();
	await f3Prep.connection.connect();
	const f3Disp = f3Attempt.dispose();
	await new Promise((r) => setImmediate(r));
	assert.equal(f3ClosedReads, 1, "createdSocket.closed is read only once");
	assert.equal(f3Released, 0, "waits for the captured native close Promise");
	resolveF3Close();
	await f3Disp;
	assert.equal(f3Released, 1);

	// Constructor getProof() throwing or returning extra rejected Promise, or Proxy ownKeys throwing a TypeError with nested rejected Promise, observes the rejection (Attempt 2 F4 & Attempt 3 F4)
	for (const badGetProof of [
		() => {
			throw { nested: Promise.reject(new Error("D55 getProof throw rejection")) };
		},
		() => ({ kind: "sign-in", token: "ok", extra: Promise.reject(new Error("D55 getProof extra rejection")) }),
		() => {
			let thrownOnce = false;
			return new Proxy(
				{ kind: "sign-in", token: "ok" },
				{
					ownKeys(t) {
						if (!thrownOnce) {
							thrownOnce = true;
							const te = new TypeError("reflective TypeError");
							te.nested = Promise.reject(new Error("D55 reflective TypeError rejection"));
							throw te;
						}
						return Reflect.ownKeys(t);
					},
				},
			);
		},
	]) {
		const f4Presenter = createCredentialPresenterTarget({
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			clock,
			getProof: badGetProof,
			issueKey: () => ({ ok: false, code: "proof-refused" }),
			connectWithKey: async () => ({}),
		});
		assert.throws(() => f4Presenter.createCredentialAttempt(undefined, { releaseUnused() {} }));
	}
	await new Promise((r) => setImmediate(r));

	// Response reflection advancing clock to >= validBeforeMonotonicMs returns issuer-unavailable (Attempt 2 F7)
	for (const endAt of [109, 110, 111]) {
		const f7Clock = createTestClock(100);
		const f7Presenter = createCredentialPresenterTarget({
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			clock: f7Clock,
			getProof: () => ({ kind: "sign-in", token: "alice-token" }),
			issueKey: () =>
				new Proxy(
					{
						ok: true,
						redemptionId: "g1-1",
						pskIdentity: "g1-1",
						secretHex: "ab".repeat(32),
						bearerToken: "ci_key_g1-1",
						proofMode: "native-tls13-external-psk-v1",
						issuer: "zorg-signin",
						principal: "alice",
						hub: "zorg-hub",
						node: "alice.0123456789abcdef",
						instanceBinding: "g1-1",
						continuationSecret: "ci_cont_1",
						validBeforeMonotonicMs: 110,
					},
					{
						ownKeys(t) {
							f7Clock.set(endAt);
							return Reflect.ownKeys(t);
						},
					},
				),
			connectWithKey: async () => ({}),
		});
		const f7Attempt = f7Presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
		const f7Res = await f7Attempt.prepareCredential();
		assert.equal(f7Res.kind, endAt < 110 ? "prepared" : "issuer-unavailable");
		await f7Attempt.dispose();
	}
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
		// Non-string secretHex (null, 7, false) even when valid secret bytes are present (F5)
		...([null, 7, false].map((badHex) => ({
			ok: true,
			redemptionId: "g1-1",
			pskIdentity: "g1-1",
			secret: new Uint8Array(32).fill(0xab),
			secretHex: badHex,
			bearerToken: "ci_key_g1-1",
			proofMode: "native-tls13-external-psk-v1",
			issuer: "zorg-signin",
			principal: "alice",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			instanceBinding: "g1-1",
			continuationSecret: "ci_cont_1",
			validBeforeMonotonicMs: clock.now() + 60_000,
		}))),
	];

	for (const c of unavailableCases) {
		currentResponse = c;
		const attempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
		const res = await attempt.prepareCredential();
		assert.equal(res.kind, "issuer-unavailable");
		await attempt.dispose();
	}

	// Shadowed 31-byte Uint8Array secret and own byteLength getter on in-process secret are rejected without calling the getter (Attempt 4 F3)
	let secretByteLengthGetterCalls = 0;
	const shadowed31 = new Uint8Array(31).fill(7);
	Object.defineProperty(shadowed31, "byteLength", { value: 32 });
	const getter32 = new Uint8Array(32).fill(7);
	Object.defineProperty(getter32, "byteLength", {
		get() {
			secretByteLengthGetterCalls += 1;
			return 32;
		},
	});
	for (const badSecretBytes of [shadowed31, getter32]) {
		currentResponse = {
			ok: true,
			redemptionId: "g1-1",
			pskIdentity: "g1-1",
			secret: badSecretBytes,
			bearerToken: "ci_key_g1-1",
			proofMode: "native-tls13-external-psk-v1",
			issuer: "zorg-signin",
			principal: "alice",
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			instanceBinding: "g1-1",
			continuationSecret: "ci_cont_1",
			validBeforeMonotonicMs: clock.now() + 60_000,
		};
		const attempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
		const res = await attempt.prepareCredential();
		assert.equal(res.kind, "issuer-unavailable");
		await attempt.dispose();
	}
	assert.equal(secretByteLengthGetterCalls, 0, "D54 must not invoke own byteLength getter on secret");

	// One-shot Proxy getPrototypeOf throw with nested rejected Promise on in-process secret is observed by readExactUint8Array (Attempt 5 F2)
	let thrownSecretProxyOnce = false;
	const proxySecret = new Proxy(new Uint8Array(32).fill(7), {
		getPrototypeOf(t) {
			if (!thrownSecretProxyOnce) {
				thrownSecretProxyOnce = true;
				throw { nested: Promise.reject(new Error("D55 unobserved rejection from secret reflection")) };
			}
			return Reflect.getPrototypeOf(t);
		},
	});
	currentResponse = {
		ok: true,
		redemptionId: "g1-1",
		pskIdentity: "g1-1",
		secret: proxySecret,
		bearerToken: "ci_key_g1-1",
		proofMode: "native-tls13-external-psk-v1",
		issuer: "zorg-signin",
		principal: "alice",
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		instanceBinding: "g1-1",
		continuationSecret: "ci_cont_1",
		validBeforeMonotonicMs: clock.now() + 60_000,
	};
	const proxySecAttempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	assert.equal((await proxySecAttempt.prepareCredential()).kind, "issuer-unavailable");
	await proxySecAttempt.dispose();
	await new Promise((r) => setImmediate(r));

	// Single-pass descriptor read on malformed getProof() and malformed issueKey() response (Attempt 7 F2)
	const proofReads = { kind: 0, token: 0, extra: 0 };
	const countingProofPresenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () =>
			new Proxy(
				{ kind: "sign-in", token: "alice-token", extra: 0 },
				{
					getOwnPropertyDescriptor(t, p) {
						if (p in proofReads) proofReads[p] += 1;
						return Reflect.getOwnPropertyDescriptor(t, p);
					},
				},
			),
		issueKey: () => ({ ok: false, code: "proof-refused" }),
		connectWithKey: async () => ({}),
	});
	assert.throws(() => countingProofPresenter.createCredentialAttempt(undefined, { releaseUnused() {} }), TypeError);
	assert.deepEqual(proofReads, { kind: 1, token: 1, extra: 1 }, "malformed getProof() reads each descriptor once");

	const issueReads = { ok: 0, code: 0, extra: 0 };
	currentResponse = new Proxy(
		{ ok: false, code: "proof-refused", extra: 0 },
		{
			getOwnPropertyDescriptor(t, p) {
				if (p in issueReads) issueReads[p] += 1;
				return Reflect.getOwnPropertyDescriptor(t, p);
			},
		},
	);
	const countingIssueAttempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	assert.equal((await countingIssueAttempt.prepareCredential()).kind, "issuer-unavailable");
	await countingIssueAttempt.dispose();
	assert.deepEqual(issueReads, { ok: 1, code: 1, extra: 1 }, "malformed issueKey() reads each descriptor once");

	// Attempt 7 F2 controls: well-formed results read each descriptor once; a nested container is read no more
	// often than readPlainJson alone reads it; an earlier descriptor throw still observes a rejected-promise sibling.
	let proofFactory = () => ({ kind: "sign-in", token: "alice-token" });
	const proofControlPresenter = createCredentialPresenterTarget({
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		clock,
		getProof: () => proofFactory(),
		issueKey: () => ({ ok: false, code: "proof-refused" }),
		connectWithKey: async () => ({}),
	});

	const validProofReads = {};
	proofFactory = () => countingProxy({ kind: "sign-in", token: "alice-token" }, validProofReads);
	const validProofAttempt = proofControlPresenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	await validProofAttempt.dispose();
	assert.deepEqual(validProofReads, { kind: 1, token: 1 }, "well-formed getProof() reads each descriptor once");

	const baselineTokenReads = {};
	assert.equal(readPlainJson(countingProxy(tokenWithGetter(), baselineTokenReads)).ok, false);
	const nestedTokenReads = {};
	proofFactory = () => ({ kind: "sign-in", token: countingProxy(tokenWithGetter(), nestedTokenReads) });
	assert.throws(() => proofControlPresenter.createCredentialAttempt(undefined, { releaseUnused() {} }), TypeError);
	assert.deepEqual(nestedTokenReads, baselineTokenReads, "refused nested token is walked only by readPlainJson");

	const throwingProofReads = {};
	proofFactory = () =>
		countingProxy({ kind: "sign-in", token: Promise.reject(new Error("D55 sibling rejection in getProof()")) }, throwingProofReads, "kind");
	assert.throws(() => proofControlPresenter.createCredentialAttempt(undefined, { releaseUnused() {} }), TypeError);
	assert.deepEqual(throwingProofReads, { kind: 1, token: 1 }, "earlier proof descriptor throw reads each descriptor once");

	const validRefusalReads = {};
	currentResponse = countingProxy({ ok: false, code: "proof-refused" }, validRefusalReads);
	const validRefusalAttempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	assert.deepEqual(await validRefusalAttempt.prepareCredential(), { kind: "issuer-refused", code: "proof-refused" });
	await validRefusalAttempt.dispose();
	assert.deepEqual(validRefusalReads, { ok: 1, code: 1 }, "well-formed issueKey() refusal reads each descriptor once");

	const baselineNestedCodeReads = {};
	assert.equal(readPlainJson({ ok: false, code: countingProxy({ reason: "x" }, baselineNestedCodeReads) }).ok, true);
	const nestedCodeReads = {};
	currentResponse = { ok: false, code: countingProxy({ reason: "x" }, nestedCodeReads) };
	const nestedCodeAttempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	assert.equal((await nestedCodeAttempt.prepareCredential()).kind, "issuer-unavailable");
	await nestedCodeAttempt.dispose();
	assert.deepEqual(nestedCodeReads, baselineNestedCodeReads, "nested issueKey() container is walked only by readPlainJson");

	const throwingIssueReads = {};
	currentResponse = countingProxy(
		{ ok: false, code: Promise.reject(new Error("D55 sibling rejection in issueKey()")) },
		throwingIssueReads,
		"ok",
	);
	const throwingIssueAttempt = presenter.createCredentialAttempt(undefined, { releaseUnused() {} });
	assert.equal((await throwingIssueAttempt.prepareCredential()).kind, "issuer-unavailable");
	await throwingIssueAttempt.dispose();
	assert.deepEqual(throwingIssueReads, { ok: 1, code: 1 }, "earlier issueKey() descriptor throw reads each descriptor once");
	await new Promise((r) => setImmediate(r));

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
