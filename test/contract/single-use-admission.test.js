// single-use-admission - CONTRACT.md's row, through CIss3, for zorg's D10-E2.
//
// Tests single-use redemption, idempotent repeat completion for the same use.lifecycle (committed, uncertain,
// and repeated rejected reuse) vs distinct rejected uses, live vs expired reuse (calling requestAdmissionTermination
// only while clock.now() < validBeforeMonotonicMs), all recordAdmissionRedemption outcomes, restart generation
// refusal, and D72 compositionSettled completion across construction unwind, genuinely no-channel attempts, and
// both completion orderings of carrierAcquisitionSettled() and the queued acceptPskChannel(channel) continuation.
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

const verifier = {
	issuer: "zorg-signin",
	verify: (cred) => (cred === "alice-token" ? { principal: "alice", session: "s1" } : null),
};

function makeUse(recordOutcome = { kind: "recorded" }, state = "established", sessionId = "sess-1") {
	let terminated = 0;
	let recordCalls = 0;
	return {
		get terminated() {
			return terminated;
		},
		get recordCalls() {
			return recordCalls;
		},
		use: {
			lifecycle: {
				readAdmissionUse: () => ({ state, sessionId }),
			},
			control: {
				requestAdmissionTermination() {
					terminated += 1;
				},
			},
			redemption: {
				recordAdmissionRedemption(...args) {
					recordCalls += 1;
					if (typeof recordOutcome === "function") return recordOutcome(...args);
					return recordOutcome;
				},
			},
		},
	};
}

test("CIss3, D10-E2: single-use admission, idempotent use.lifecycle repeats, live vs expired reuse termination, recordAdmissionRedemption outcomes, and restart generation refusal", async () => {
	const clock = createTestClock();
	const reports = [];
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		keyLifetimeMs: 60_000,
		keyRetentionMs: 180_000,
		onKeyReuse: (r) => reports.push(r),
	});

	// 1) Explicit unrecorded refusals ("authorization-expired", "expired", "invalid-authorization", "invalid-redemption", "inactive", "capacity")
	// do not spend the key, so a subsequent valid attempt redeems it
	const key1 = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(key1.ok, true);

	for (const explicitRefusal of [
		"authorization-expired",
		"expired",
		"invalid-authorization",
		"invalid-redemption",
		"inactive",
		"capacity",
	]) {
		const arr = {};
		const look = issuer.resolvePsk(key1.pskIdentity, { arrival: arr });
		const u = makeUse({ kind: explicitRefusal });
		assert.equal(issuer.completePskProof({ arrival: arr, use: u.use }, { arrival: arr, lookupRef: look.lookupRef }), "refused");
		assert.equal(u.terminated, 0);
	}
	assert.equal(reports.length, 0);

	// First recorded presentation succeeds
	const arrFirst = {};
	const lookFirst = issuer.resolvePsk(key1.pskIdentity, { arrival: arrFirst });
	const uFirst = makeUse({ kind: "recorded" }, "established", "sess-first");
	assert.equal(
		issuer.completePskProof({ arrival: arrFirst, use: uFirst.use }, { arrival: arrFirst, lookupRef: lookFirst.lookupRef }),
		"redeemed",
	);
	assert.equal(uFirst.recordCalls, 1);

	// Idempotent repeat with the exact same use.lifecycle returns "redeemed" without calling recordAdmissionRedemption again or reporting reuse (o:F4)
	assert.equal(
		issuer.completePskProof({ arrival: arrFirst, use: uFirst.use }, { arrival: arrFirst, lookupRef: lookFirst.lookupRef }),
		"redeemed",
	);
	assert.equal(uFirst.recordCalls, 1);
	assert.equal(reports.length, 0);

	// Second presentation with a distinct use.lifecycle while key is live (clock < validBeforeMonotonicMs)
	// refuses the second presentation, calls requestAdmissionTermination() on the first session, and reports once
	const arrSecond = {};
	const lookSecond = issuer.resolvePsk(key1.pskIdentity, { arrival: arrSecond });
	const uSecond = makeUse({ kind: "recorded" }, "pending", null);
	assert.equal(
		issuer.completePskProof({ arrival: arrSecond, use: uSecond.use }, { arrival: arrSecond, lookupRef: lookSecond.lookupRef }),
		"refused",
	);
	assert.equal(uFirst.terminated, 1, "first session terminated on live reuse");
	assert.equal(reports.length, 1);
	assert.equal(reports[0].firstSessionStopped, true);
	assert.equal(reports[0].firstSession, "sess-first");
	assert.equal(reports[0].secondSession, null);
	assert.notEqual(reports[0].firstUseId, reports[0].secondUseId);

	// Repeating completePskProof with the SAME rejected uSecond.use.lifecycle returns "refused" without emitting another report or calling termination again (o:F2)
	assert.equal(
		issuer.completePskProof({ arrival: arrSecond, use: uSecond.use }, { arrival: arrSecond, lookupRef: lookSecond.lookupRef }),
		"refused",
	);
	assert.equal(uFirst.terminated, 1, "not terminated a second time for same rejected lifecycle");
	assert.equal(reports.length, 1, "not reported a second time for same rejected lifecycle");

	// Advance clock past validBeforeMonotonicMs (+60_000ms): a third distinct presentation is refused and reported
	// with firstSessionStopped: false, and does NOT call requestAdmissionTermination()
	clock.advance(60_000);
	const arrThird = {};
	const lookThird = issuer.resolvePsk(key1.pskIdentity, { arrival: arrThird });
	const uThird = makeUse({ kind: "recorded" });
	assert.equal(
		issuer.completePskProof({ arrival: arrThird, use: uThird.use }, { arrival: arrThird, lookupRef: lookThird.lookupRef }),
		"refused",
	);
	assert.equal(uFirst.terminated, 1, "not terminated after key expired");
	assert.equal(reports.length, 2);
	assert.equal(reports[1].firstSessionStopped, false);
	assert.notEqual(reports[1].secondUseId, reports[0].secondUseId);

	// 2) Uncertain state when recordAdmissionRedemption throws: marks key uncertain, calls requestAdmissionTermination,
	// idempotent repeat on same uncertain lifecycle returns "refused" without reporting reuse, and distinct lifecycle triggers reuse report
	const key2 = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		continuationSecret: key1.continuationSecret,
	});
	const arrUncertain = {};
	const lookUncertain = issuer.resolvePsk(key2.pskIdentity, { arrival: arrUncertain });
	const uUncertain = makeUse(() => {
		throw new Error("storage fault during recordAdmissionRedemption");
	});
	assert.equal(
		issuer.completePskProof({ arrival: arrUncertain, use: uUncertain.use }, { arrival: arrUncertain, lookupRef: lookUncertain.lookupRef }),
		"refused",
	);
	assert.equal(uUncertain.terminated, 1);
	assert.equal(reports.length, 2, "initial uncertain fault is not a second use");
	// Repeat on same uncertain lifecycle -> still "refused", no reuse report
	assert.equal(
		issuer.completePskProof({ arrival: arrUncertain, use: uUncertain.use }, { arrival: arrUncertain, lookupRef: lookUncertain.lookupRef }),
		"refused",
	);
	assert.equal(reports.length, 2);

	// 3) Restart refusal: a fresh CredentialIssuer instance has a new generation and refuses keys from the old instance
	const restartedIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
	});
	assert.notEqual(restartedIssuer.generation, issuer.generation);
	assert.deepEqual(restartedIssuer.resolvePsk(key2.pskIdentity), { kind: "unknown" });
});

test("CIss3, A2, D72, D10-E2: beginPskArrival compositionSettled sequence across construction unwind, genuinely no-channel attempts, and both completion orderings of carrierAcquisitionSettled() and queued acceptPskChannel(channel)", async () => {
	const clock = createTestClock();
	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
	});

	// 1) Construction unwind: if callbacks is invalid after reserveAdmissionUse succeeded, finishAdmissionAcquisition is called immediately
	let finishedUnwind = 0;
	const unwindPool = {
		reserveAdmissionUse() {
			return {
				kind: "reserved",
				use: {
					lifecycle: { readAdmissionUse: () => ({ state: "pending" }) },
					control: { requestAdmissionTermination() {} },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
					finishAdmissionAcquisition() {
						finishedUnwind += 1;
					},
				},
			};
		},
	};
	assert.throws(() => issuer.beginPskArrival(unwindPool, null, {}), TypeError);
	assert.equal(finishedUnwind, 1, "finishAdmissionAcquisition called on construction unwind");

	// 2) Genuinely no-channel attempt: carrierAcquisitionSettled() called when acceptPskChannel was never called
	const keyNoChan = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	let finishedNoChan = 0;
	let terminatedNoChan = 0;
	const noChanPool = {
		reserveAdmissionUse() {
			return {
				kind: "reserved",
				use: {
					lifecycle: { readAdmissionUse: () => ({ state: "pending" }) },
					control: { requestAdmissionTermination() { terminatedNoChan += 1; } },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
					finishAdmissionAcquisition() { finishedNoChan += 1; },
				},
			};
		},
	};
	const attemptNoChan = issuer.beginPskArrival(noChanPool, { acceptAdmission() {} }, {});
	assert.equal(attemptNoChan.kind, "reserved");
	const resNoChan = attemptNoChan.resolvePsk(keyNoChan.pskIdentity);
	assert.equal(
		attemptNoChan.completePskProof({ arrival: attemptNoChan.arrival, lookupRef: resNoChan.lookupRef }),
		"redeemed",
	);
	assert.equal(finishedNoChan, 0);
	attemptNoChan.carrierAcquisitionSettled();
	await attemptNoChan.settled;
	assert.equal(terminatedNoChan, 1, "no-channel attempt after redemption revokes admission use");
	assert.equal(finishedNoChan, 1, "finishAdmissionAcquisition called on no-channel attempt");

	// 3) Both completion orderings when a channel is produced (o:F1):
	// Order A: acceptPskChannel(channel) called, then carrierAcquisitionSettled() called synchronously WHILE host continuation is still queued
	// Order B: acceptPskChannel(channel) called, host continuation completes first, and THEN carrierAcquisitionSettled() is called
	for (const order of ["carrier-settles-while-host-queued", "host-continuation-settles-first"]) {
		const key = await issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			continuationSecret: keyNoChan.continuationSecret,
		});
		let finished = 0;
		let acceptedHandoff = null;
		let channelClosed = 0;
		const pool = {
			reserveAdmissionUse() {
				return {
					kind: "reserved",
					use: {
						lifecycle: { readAdmissionUse: () => ({ state: "admitted" }) },
						control: { requestAdmissionTermination() {} },
						redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
						sealAdmissionHandoff(ch) {
							return { kind: "sealed", handoff: { sealedChannel: ch } };
						},
						finishAdmissionAcquisition() {
							finished += 1;
						},
					},
				};
			},
		};
		const attempt = issuer.beginPskArrival(
			pool,
			{
				acceptAdmission(h) {
					acceptedHandoff = h;
				},
			},
			{},
		);
		const look = attempt.resolvePsk(key.pskIdentity);
		assert.equal(attempt.completePskProof({ arrival: attempt.arrival, lookupRef: look.lookupRef }), "redeemed");

		const channel = { close() { channelClosed += 1; } };
		attempt.acceptPskChannel(channel);

		if (order === "carrier-settles-while-host-queued") {
			// Carrier settles immediately while acceptPskChannel's microtask is still queued
			attempt.carrierAcquisitionSettled();
			assert.equal(finished, 0, "must wait for queued host continuation before finishAdmissionAcquisition");
			await attempt.settled;
			assert.equal(finished, 1);
			assert.deepEqual(acceptedHandoff, { sealedChannel: channel });
			assert.equal(channelClosed, 0);
		} else {
			// Let the queued host continuation run first
			await new Promise((r) => queueMicrotask(r));
			assert.deepEqual(acceptedHandoff, { sealedChannel: channel });
			assert.equal(finished, 0, "must wait for carrierAcquisitionSettled before finishAdmissionAcquisition");
			attempt.carrierAcquisitionSettled();
			await attempt.settled;
			assert.equal(finished, 1);
			assert.equal(channelClosed, 0);
		}
	}

	// 4) Missing sealAdmissionHandoff on use never offers a raw unsealed channel to acceptAdmission (F8)
	const keyMissingSeal = await issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		continuationSecret: keyNoChan.continuationSecret,
	});
	let unsealedOffers = 0;
	let unsealedChannelClosed = 0;
	let unsealedTerminated = 0;
	const missingSealPool = {
		reserveAdmissionUse() {
			return {
				kind: "reserved",
				use: {
					lifecycle: { readAdmissionUse: () => ({ state: "admitted" }) },
					control: { requestAdmissionTermination() { unsealedTerminated += 1; } },
					redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
					finishAdmissionAcquisition() {},
				},
			};
		},
	};
	const attemptMissingSeal = issuer.beginPskArrival(
		missingSealPool,
		{ acceptAdmission() { unsealedOffers += 1; } },
		{},
	);
	const lookMissingSeal = attemptMissingSeal.resolvePsk(keyMissingSeal.pskIdentity);
	assert.equal(
		attemptMissingSeal.completePskProof({ arrival: attemptMissingSeal.arrival, lookupRef: lookMissingSeal.lookupRef }),
		"redeemed",
	);
	attemptMissingSeal.acceptPskChannel({ close() { unsealedChannelClosed += 1; } });
	attemptMissingSeal.carrierAcquisitionSettled();
	await attemptMissingSeal.settled;
	assert.equal(unsealedOffers, 0, "never offers raw unsealed channel when sealAdmissionHandoff is missing");
	assert.equal(unsealedTerminated, 1);
	assert.equal(unsealedChannelClosed, 1);

	// 5) AGP AdmissionRedemptionResult with context ({ kind: "recorded", context: { redemptionId, lifecycle } }) and
	// { kind: "refused", reason }, plus redeemBearer path and D55 rejected-Promise observation on onKeyReuse / requestAdmissionTermination (F1, F4, F10)
	const agpIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock,
		onKeyReuse: () => Promise.reject(new Error("D55 onKeyReuse rejection")),
	});
	const agpKey = await agpIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		proofMode: "bearer",
	});
	assert.equal(agpKey.ok, true);

	// Explicit AGP { kind: "refused", reason: "inactive" } preserves the unspent key
	const refusedUse = makeUse(() => ({ kind: "refused", reason: "inactive" }));
	assert.equal(agpIssuer.redeemBearer(refusedUse.use, agpKey.bearerToken, "alice.0123456789abcdef"), "refused");
	assert.equal(refusedUse.terminated, 0);

	// AGP { kind: "recorded", context: { redemptionId, lifecycle } } redeems the bearer key
	let recordedUseObj;
	recordedUseObj = makeUse((id) => ({
		kind: "recorded",
		context: { redemptionId: id, lifecycle: recordedUseObj.use.lifecycle },
	}));
	recordedUseObj.use.control.requestAdmissionTermination = () => Promise.reject(new Error("D55 termination rejection"));
	assert.equal(agpIssuer.redeemBearer(recordedUseObj.use, agpKey.bearerToken, "alice.0123456789abcdef"), "redeemed");

	// Second bearer presentation triggers live termination and onKeyReuse (both returning rejected Promises, consumed via D55)
	const reuseUseObj = makeUse();
	assert.equal(agpIssuer.redeemBearer(reuseUseObj.use, agpKey.bearerToken, "alice.0123456789abcdef"), "refused");
	await new Promise((r) => setImmediate(r));

	// 6) Reuse where readAdmissionUse advances clock to >= validBeforeMonotonicMs does NOT call requestAdmissionTermination (Attempt 2 F6),
	// and repeating completion for an original committed or uncertain lifecycle after terminal slot compaction remains idempotent with 0 new reports (Attempt 2 F8)
	for (const endAt of [109, 110, 111]) {
		const f6Clock = createTestClock(100);
		const f6Reports = [];
		const f6Issuer = createCredentialIssuer({
			hub: "zorg-hub",
			verifiers: [verifier],
			clock: f6Clock,
			keyLifetimeMs: 10,
			keyRetentionMs: 100,
			onKeyReuse: (r) => f6Reports.push(r),
		});
		const f6Key = await f6Issuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			proofMode: "bearer",
		});
		let advanceInRead = false;
		let termCount = 0;
		const f6Use1 = {
			lifecycle: {
				readAdmissionUse() {
					if (advanceInRead) f6Clock.set(endAt);
					return { state: "established", sessionId: "s-f6" };
				},
			},
			control: { requestAdmissionTermination() { termCount += 1; } },
			redemption: { recordAdmissionRedemption: () => ({ kind: "recorded" }) },
		};
		assert.equal(f6Issuer.redeemBearer(f6Use1, f6Key.bearerToken), "redeemed");
		f6Clock.set(109);
		advanceInRead = true;
		assert.equal(f6Issuer.redeemBearer(makeUse().use, f6Key.bearerToken), "refused");
		assert.equal(termCount, endAt < 110 ? 1 : 0);
		assert.equal(f6Reports[0].firstSessionStopped, endAt < 110);
	}

	// Compacted original lifecycle repeat idempotence (Attempt 2 F8)
	const f8Clock = createTestClock(100);
	const f8Reports = [];
	const f8Issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		clock: f8Clock,
		keyLifetimeMs: 10,
		keyRetentionMs: 100,
		onKeyReuse: (r) => f8Reports.push(r),
	});
	const f8Key = await f8Issuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		proofMode: "bearer",
	});
	const f8Use = makeUse({ kind: "recorded" }, "terminal", "s-f8");
	assert.equal(f8Issuer.redeemBearer(f8Use.use, f8Key.bearerToken), "redeemed");
	f8Clock.set(110);
	f8Issuer.sweepLeases(); // compacts terminal slot at validBeforeMonotonicMs (110) while key is retained until 200
	assert.equal(f8Issuer.redeemBearer(f8Use.use, f8Key.bearerToken), "redeemed", "compacted committed lifecycle stays idempotent");
	assert.equal(f8Reports.length, 0, "no false reuse report after terminal compaction");

	// 7) Reentrant redemption (from recordAdmissionRedemption callback or result Proxy reflection) never admits a second distinct lifecycle (Attempt 3 F1),
	// and single-pass descriptor reading on recordAdmissionRedemption result refuses changing descriptors and observes rejected Promises (Attempt 3 F3)
	for (const reentryVariant of ["callback", "reflection"]) {
		const reIssuer = createCredentialIssuer({
			hub: "zorg-hub",
			verifiers: [verifier],
			clock,
		});
		const reKey = await reIssuer.issueAdmissionKey({
			proof: { kind: "sign-in", token: "alice-token" },
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
			proofMode: "bearer",
		});
		const firstUse = makeUse();
		const secondUse = makeUse();
		let nestedOutcome = null;
		let entered = false;
		firstUse.use.redemption.recordAdmissionRedemption = (id) => {
			const res = { kind: "recorded", context: { redemptionId: id, lifecycle: firstUse.use.lifecycle } };
			if (reentryVariant === "callback") {
				nestedOutcome = reIssuer.redeemBearer(secondUse.use, reKey.bearerToken);
				return res;
			}
			return new Proxy(res, {
				ownKeys(t) {
					if (!entered) {
						entered = true;
						nestedOutcome = reIssuer.redeemBearer(secondUse.use, reKey.bearerToken);
					}
					return Reflect.ownKeys(t);
				},
			});
		};
		const outerOutcome = reIssuer.redeemBearer(firstUse.use, reKey.bearerToken);
		assert.equal(outerOutcome, "redeemed");
		assert.equal(nestedOutcome, "refused", `reentrant ${reentryVariant} second lifecycle must be refused`);
		assert.equal(
			reIssuer.verifyRedeemed({
				redemptionId: reKey.redemptionId,
				lifecycle: firstUse.use.lifecycle,
				remoteNodeId: reKey.node,
			}).ok,
			true,
		);
		assert.equal(
			reIssuer.verifyRedeemed({
				redemptionId: reKey.redemptionId,
				lifecycle: secondUse.use.lifecycle,
				remoteNodeId: reKey.node,
			}).ok,
			false,
		);
	}

	// Single-pass descriptor read on recordAdmissionRedemption result (Attempt 3 F3)
	const f3Key = await agpIssuer.issueAdmissionKey({
		proof: { kind: "sign-in", token: "alice-token" },
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
		proofMode: "bearer",
		continuationSecret: agpKey.continuationSecret,
	});
	let f3KindReads = 0;
	const f3ChangingUse = makeUse(() =>
		new Proxy(
			{ kind: "recorded" },
			{
				getOwnPropertyDescriptor(target, prop) {
					if (prop === "kind") {
						f3KindReads += 1;
						return {
							configurable: true,
							enumerable: true,
							value: f3KindReads === 1 ? Promise.reject(new Error("D55 first-read rejection")) : "recorded",
						};
					}
					return Reflect.getOwnPropertyDescriptor(target, prop);
				},
			},
		),
	);
	assert.equal(agpIssuer.redeemBearer(f3ChangingUse.use, f3Key.bearerToken), "refused");
	assert.equal(f3KindReads, 1, "recordAdmissionRedemption result kind descriptor is read only once");
	await new Promise((r) => setImmediate(r));
});
