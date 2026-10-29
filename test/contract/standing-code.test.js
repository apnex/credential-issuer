// standing-code - CONTRACT.md's row, through CIss1, for zorg's D10-E2.
//
// Tests sign-in verification, allowStandingCode (including minterPrincipal !== identity), SHA-256 hashing without
// raw secret storage, listStandingCodes, revokeStandingCode, wall-clock expiry, createMemoryStandingCodeStore and
// createFileStandingCodeStore across restarts, symlink/directory/pre-rename write-failure "code-store-unwritable"
// fail-closed checks, post-rename directory fsyncSync failure quarantining in-memory standing-code operations and
// recovering on restart, FIFO/non-regular-file and corrupt header/line/duplicate "code-store-corrupt" checks before
// reading, and D54/D55 plain-data callback protection.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createCredentialIssuer, createMemoryStandingCodeStore } from "@apnex/credential-issuer";
import { createFileStandingCodeStore } from "@apnex/credential-issuer/machine";

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

function createTestWallClock(initialMs = 1_700_000_000_000) {
	let nowMs = initialMs;
	return {
		nowMs: () => nowMs,
		advance: (ms) => {
			nowMs += ms;
		},
		set: (ms) => {
			nowMs = ms;
		},
	};
}

const verifier = {
	issuer: "zorg-signin",
	verify(cred) {
		if (cred === "signin-alice") return { principal: "alice", session: "sess-alice" };
		if (cred === "signin-bob") return { principal: "bob", session: "sess-bob" };
		return null;
	},
};

test("CIss1, D10-E2: mintStandingCode, listStandingCodes, revokeStandingCode, SHA-256 hashing, minterPrincipal !== identity, and immediate revocation/expiry enforcement", async () => {
	const clock = createTestClock();
	const wallClock = createTestWallClock();
	const store = createMemoryStandingCodeStore();

	const issuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: store,
		clock,
		wallClock,
		allowStandingCode({ minterPrincipal, minterIssuer, identity }) {
			return minterIssuer === "zorg-signin" && minterPrincipal === "alice" && (identity === "alice" || identity === "buildbot");
		},
	});

	// Unverified sign-in proof -> proof-refused
	assert.deepEqual(await issuer.mintStandingCode({ proof: "bad-token", identity: "alice" }), {
		ok: false,
		code: "proof-refused",
	});

	// Invalid identity -> invalid-identity
	assert.deepEqual(await issuer.mintStandingCode({ proof: "signin-alice", identity: "Bad_Identity" }), {
		ok: false,
		code: "invalid-identity",
	});

	// Past or current expiresAtMs -> invalid-expiry
	assert.deepEqual(
		await issuer.mintStandingCode({ proof: "signin-alice", identity: "alice", expiresAtMs: wallClock.nowMs() }),
		{ ok: false, code: "invalid-expiry" },
	);

	// Forbidden identity -> forbidden-identity
	assert.deepEqual(await issuer.mintStandingCode({ proof: "signin-alice", identity: "other" }), {
		ok: false,
		code: "forbidden-identity",
	});

	// Mint standing code for "buildbot" (minterPrincipal "alice" !== identity "buildbot")
	const minted = await issuer.mintStandingCode({
		proof: "signin-alice",
		identity: "buildbot",
		expiresAtMs: wallClock.nowMs() + 10_000,
	});
	assert.equal(minted.ok, true);
	assert.match(minted.code, /^ci_code_[0-9a-f]{64}$/);
	assert.match(minted.codeId, /^sc_[0-9a-f]{16}$/);
	assert.equal(minted.identity, "buildbot");
	assert.equal(minted.minterPrincipal, "alice");
	assert.equal(minted.minterIssuer, "zorg-signin");

	// Stored record holds only SHA-256 hash, never raw secret
	const stored = store.load();
	assert.equal(stored.length, 1);
	assert.equal("code" in stored[0], false);
	assert.match(stored[0].codeHash, /^[0-9a-f]{64}$/);
	assert.equal(JSON.stringify(stored).includes(minted.code), false);

	// Standing code itself is never accepted as proof to mint another standing code
	assert.deepEqual(await issuer.mintStandingCode({ proof: minted.code, identity: "buildbot" }), {
		ok: false,
		code: "proof-refused",
	});

	// listStandingCodes returns only the caller's public summaries without code or codeHash
	const listedAlice = await issuer.listStandingCodes({ proof: "signin-alice" });
	assert.equal(listedAlice.ok, true);
	assert.equal(listedAlice.codes.length, 1);
	assert.equal("code" in listedAlice.codes[0], false);
	assert.equal("codeHash" in listedAlice.codes[0], false);
	assert.equal(listedAlice.codes[0].codeId, minted.codeId);
	assert.equal(listedAlice.codes[0].identity, "buildbot");

	const listedBob = await issuer.listStandingCodes({ proof: "signin-bob" });
	assert.deepEqual(listedBob, { ok: true, codes: [] });

	// Standing code yields an admission key for buildbot.<16 hex> while live
	const key1 = await issuer.issueAdmissionKey({
		grantType: "client_credentials",
		clientSecret: minted.code,
		hub: "zorg-hub",
		node: "buildbot.0123456789abcdef",
	});
	assert.equal(key1.ok, true);
	assert.equal(key1.principal, "buildbot");
	assert.equal(key1.issuer, "zorg-signin");

	// Bob cannot revoke Alice's standing code
	assert.deepEqual(await issuer.revokeStandingCode({ proof: "signin-bob", codeId: minted.codeId }), {
		ok: false,
		code: "not-found",
	});

	// Alice revokes the standing code -> yields no admission key from that moment on
	wallClock.advance(500);
	const revoked = await issuer.revokeStandingCode({ proof: "signin-alice", codeId: minted.codeId });
	assert.deepEqual(revoked, { ok: true, codeId: minted.codeId, revokedAtMs: wallClock.nowMs() });

	const afterRevoke = await issuer.issueAdmissionKey({
		grantType: "client_credentials",
		clientSecret: minted.code,
		hub: "zorg-hub",
		node: "buildbot.0123456789abcdef",
		continuationSecret: key1.continuationSecret,
	});
	assert.deepEqual(afterRevoke, { ok: false, code: "proof-refused" });

	// Mint a second code with expiry and advance wallClock to exact expiry -> yields no admission key
	const minted2 = await issuer.mintStandingCode({
		proof: "signin-alice",
		identity: "alice",
		expiresAtMs: wallClock.nowMs() + 1_000,
	});
	assert.equal(minted2.ok, true);
	wallClock.advance(1_000);
	const afterExpiry = await issuer.issueAdmissionKey({
		grantType: "client_credentials",
		clientSecret: minted2.code,
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.deepEqual(afterExpiry, { ok: false, code: "proof-refused" });
});

test("CIss1, D10-E2: createFileStandingCodeStore persistence across restart, symlink/directory refusal, FIFO/non-regular-file rejection before open, corrupt file rejection, and pre-rename vs post-rename write failures", async (t) => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ci-standing-code-"));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

	const filePath = path.join(dir, "codes.log");
	const clock = createTestClock();
	const wallClock = createTestWallClock();

	// 1) Mint and revoke persist to disk and recover across a new CredentialIssuer instance
	const store1 = createFileStandingCodeStore(filePath);
	assert.deepEqual(store1.load(), []);

	const issuer1 = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: store1,
		clock,
		wallClock,
	});
	const m1 = await issuer1.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	const m2 = await issuer1.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.equal(m1.ok && m2.ok, true);
	await issuer1.revokeStandingCode({ proof: "signin-alice", codeId: m1.codeId });

	// Reopen in a fresh store and issuer instance
	const store2 = createFileStandingCodeStore(filePath);
	const issuer2 = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: store2,
		clock,
		wallClock,
	});
	// m1 remains revoked across restart, m2 remains valid
	assert.deepEqual(
		await issuer2.issueAdmissionKey({
			grantType: "client_credentials",
			clientSecret: m1.code,
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "proof-refused" },
	);
	const k2 = await issuer2.issueAdmissionKey({
		grantType: "client_credentials",
		clientSecret: m2.code,
		hub: "zorg-hub",
		node: "alice.0123456789abcdef",
	});
	assert.equal(k2.ok, true);

	// 2) Symlink and directory at filePath or ${filePath}.tmp are refused with code: "code-store-unwritable"
	const symPath = path.join(dir, "sym.log");
	fs.symlinkSync(filePath, symPath);
	assert.throws(
		() => createFileStandingCodeStore(symPath).load(),
		(err) => err?.code === "code-store-unwritable",
	);
	assert.throws(
		() => createFileStandingCodeStore(dir).load(),
		(err) => err?.code === "code-store-unwritable",
	);
	const tmpSymTarget = path.join(dir, "with-tmp-sym.log");
	fs.symlinkSync(filePath, `${tmpSymTarget}.tmp`);
	assert.throws(
		() => createFileStandingCodeStore(tmpSymTarget).load(),
		(err) => err?.code === "code-store-unwritable",
	);

	// 3) FIFO (named pipe) at filePath is rejected as "code-store-corrupt" by lstatSync BEFORE opening/reading (o:F8)
	const fifoPath = path.join(dir, "pipe.fifo");
	execFileSync("mkfifo", [fifoPath]);
	let readFileCalledOnFifo = false;
	const fifoStore = createFileStandingCodeStore(fifoPath, {
		readFileSync(...args) {
			readFileCalledOnFifo = true;
			return fs.readFileSync(...args);
		},
	});
	assert.throws(
		() => fifoStore.load(),
		(err) => err?.code === "code-store-corrupt",
	);
	assert.equal(readFileCalledOnFifo, false, "FIFO rejected before readFileSync is called");

	// 4) Corrupt header, corrupt JSON line, extra field, or duplicate codeId/codeHash rejected as "code-store-corrupt"
	const recLine = JSON.stringify(store2.load()[0]);
	const corruptPayloads = [
		"{\"store\":\"wrong\",\"version\":1}\n",
		"{\"store\":\"credential-issuer-codes\",\"version\":1}\nnot-json\n",
		`{"store":"credential-issuer-codes","version":1}\n${JSON.stringify({ ...store2.load()[0], extra: 1 })}\n`,
		`{"store":"credential-issuer-codes","version":1}\n${recLine}\n${recLine}\n`,
	];
	for (let i = 0; i < corruptPayloads.length; i++) {
		const p = path.join(dir, `corrupt-${i}.log`);
		fs.writeFileSync(p, corruptPayloads[i]);
		assert.throws(
			() => createFileStandingCodeStore(p).load(),
			(err) => err?.code === "code-store-corrupt",
		);
	}

	// 5) Pre-rename write failure leaves in-memory state and on-disk store unchanged
	const preRenamePath = path.join(dir, "pre-rename.log");
	let failWrite = false;
	const preRenameStore = createFileStandingCodeStore(preRenamePath, {
		writeFileSync(fd, data, enc) {
			if (failWrite) throw new Error("disk full before rename");
			return fs.writeFileSync(fd, data, enc);
		},
	});
	const preIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: preRenameStore,
		clock,
		wallClock,
	});
	const preMint = await preIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.equal(preMint.ok, true);
	failWrite = true;
	const failedMint = await preIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.deepEqual(failedMint, { ok: false, code: "code-store-unwritable" });
	failWrite = false;
	// Store is NOT quarantined because renameSync had not happened; preMint remains valid
	const listedAfterPreFail = await preIssuer.listStandingCodes({ proof: "signin-alice" });
	assert.equal(listedAfterPreFail.ok, true);
	assert.equal(listedAfterPreFail.codes.length, 1);

	// 6) Post-rename directory fsyncSync failure quarantines in-memory standing-code operations until restart recovery (o:F6)
	const postRenamePath = path.join(dir, "post-rename.log");
	let failDirFsync = false;
	const postRenameStore = createFileStandingCodeStore(postRenamePath, {
		fsyncSync(fd) {
			if (failDirFsync) throw new Error("parent dir fsync failure after rename");
			return fs.fsyncSync(fd);
		},
	});
	const postIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: postRenameStore,
		clock,
		wallClock,
	});
	const toRevoke = await postIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.equal(toRevoke.ok, true);
	failDirFsync = true;
	const revokeFail = await postIssuer.revokeStandingCode({ proof: "signin-alice", codeId: toRevoke.codeId });
	assert.deepEqual(revokeFail, { ok: false, code: "code-store-unwritable" });
	// Because renameSync already replaced post-rename.log on disk, postIssuer is now quarantined so the revoked code cannot be used in memory!
	assert.deepEqual(
		await postIssuer.issueAdmissionKey({
			grantType: "client_credentials",
			clientSecret: toRevoke.code,
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "code-store-unwritable" },
	);
	assert.deepEqual(await postIssuer.listStandingCodes({ proof: "signin-alice" }), {
		ok: false,
		code: "code-store-unwritable",
	});
	assert.deepEqual(await postIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" }), {
		ok: false,
		code: "code-store-unwritable",
	});
	// Restarting a fresh CredentialIssuer on the file recovers the replaced file state (where toRevoke is revoked)
	failDirFsync = false;
	const recoveredIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: createFileStandingCodeStore(postRenamePath),
		clock,
		wallClock,
	});
	const recoveredList = await recoveredIssuer.listStandingCodes({ proof: "signin-alice" });
	assert.equal(recoveredList.ok, true);
	assert.notEqual(recoveredList.codes[0].revokedAtMs, null);
	// 7) D54/D55 on StandingCodeStore.load() container (index-getter, iterator, extra-property, symbol, subclass, and rejected Promise on array)
	// and save() thrown error with getter afterRename (F2), plus sign-in expiry during async isSignInRevoked in mint, list and revoke (F3)
	const validRec = {
		codeId: "sc_0123456789abcdef",
		codeHash: "a".repeat(64),
		identity: "alice",
		minterPrincipal: "alice",
		minterIssuer: "zorg-signin",
		createdAtMs: 0,
		expiresAtMs: null,
		revokedAtMs: null,
	};
	for (const variant of ["index-getter", "iterator", "extra-property", "symbol", "subclass"]) {
		let executed = 0;
		let arr = [validRec];
		if (variant === "index-getter") {
			Object.defineProperty(arr, "0", { enumerable: true, get() { executed += 1; return validRec; } });
		}
		if (variant === "iterator") {
			arr[Symbol.iterator] = function* () { executed += 1; yield validRec; };
		}
		if (variant === "extra-property") arr.extra = Promise.reject(new Error("array extra rejection"));
		if (variant === "symbol") arr[Symbol("s")] = true;
		if (variant === "subclass") {
			class SubArray extends Array {}
			arr = new SubArray(validRec);
		}
		assert.throws(
			() => createCredentialIssuer({
				hub: "zorg-hub",
				verifiers: [verifier],
				standingCodeStore: { load: () => arr, save() {} },
				clock,
				wallClock,
			}),
			(err) => err?.code === "code-store-corrupt",
		);
		assert.equal(executed, 0, `D54 ${variant} must not invoke array getters/iterators`);
	}

	// save() throws an object whose afterRename is a getter -> getter is never called, returns code-store-unwritable
	let afterRenameGetterCalls = 0;
	const getterErrIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: {
			load: () => [],
			save() {
				throw {
					get afterRename() {
						afterRenameGetterCalls += 1;
						throw new Error("afterRename getter called");
					},
				};
			},
		},
		clock,
		wallClock,
	});
	const getterSaveRes = await getterErrIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.deepEqual(getterSaveRes, { ok: false, code: "code-store-unwritable" });
	assert.equal(afterRenameGetterCalls, 0, "afterRename getter on thrown save error is never called");

	// Single-pass afterRename descriptor read on thrown save error (Attempt 4 F1)
	const changingMem = createMemoryStandingCodeStore();
	let changingArmed = false;
	let afterRenameReads = 0;
	const changingStore = {
		load: () => changingMem.load(),
		save(recs) {
			changingMem.save(recs);
			if (changingArmed) {
				throw new Proxy(
					{ afterRename: true },
					{
						getOwnPropertyDescriptor(target, name) {
							if (name === "afterRename") {
								afterRenameReads += 1;
								return {
									enumerable: true,
									configurable: true,
									value: afterRenameReads === 1,
								};
							}
							return Reflect.getOwnPropertyDescriptor(target, name);
						},
					},
				);
			}
		},
	};
	const changingIssuer = createCredentialIssuer({
		hub: "zorg-hub",
		verifiers: [verifier],
		standingCodeStore: changingStore,
		clock,
		wallClock,
	});
	const changingMint = await changingIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
	assert.equal(changingMint.ok, true);
	changingArmed = true;
	const changingRevoke = await changingIssuer.revokeStandingCode({
		proof: "signin-alice",
		codeId: changingMint.codeId,
	});
	assert.deepEqual(changingRevoke, { ok: false, code: "code-store-unwritable" });
	assert.equal(afterRenameReads, 1, "afterRename descriptor is read at most once");
	assert.deepEqual(
		await changingIssuer.issueAdmissionKey({
			grantType: "client_credentials",
			clientSecret: changingMint.code,
			hub: "zorg-hub",
			node: "alice.0123456789abcdef",
		}),
		{ ok: false, code: "code-store-unwritable" },
		"changing-proxy post-rename failure quarantines the store",
	);

	// Sign-in expiry during async isSignInRevoked in mintStandingCode, listStandingCodes, and revokeStandingCode (F3)
	for (const method of ["mintStandingCode", "listStandingCodes", "revokeStandingCode"]) {
		const expClock = createTestClock(100);
		let armed = false;
		let checks = 0;
		const expIssuer = createCredentialIssuer({
			hub: "zorg-hub",
			verifiers: [{ issuer: "zorg-signin", verify: () => ({ principal: "alice", session: "s1", expiresAt: 110 }) }],
			clock: expClock,
			wallClock,
			async isSignInRevoked() {
				if (armed) {
					checks += 1;
					if (checks === (method === "mintStandingCode" ? 2 : 1)) {
						expClock.set(110);
					}
				}
				return false;
			},
		});
		const seeded = await expIssuer.mintStandingCode({ proof: "signin-alice", identity: "alice" });
		assert.equal(seeded.ok, true);
		armed = true;
		const expiredRes = await expIssuer[method]({
			proof: "signin-alice",
			identity: "alice",
			codeId: seeded.codeId,
		});
		assert.deepEqual(expiredRes, { ok: false, code: "proof-refused" }, `${method} refuses proof expiring during isSignInRevoked`);
	}
});
