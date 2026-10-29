/**
 * `@apnex/credential-issuer` core implementation of `CIss1`, `CIss2`, `CIss3` and `CIss4`:
 * - `CIss1`: standing-code minting, listing, revocation, and quarantine on post-rename directory-sync failure
 * - `CIss2`: `(hub, node)` exclusive leases (storing only `continuationSecretHash`), handle reservation lifecycle, and OAuth-shaped admission-key issuance
 * - `CIss3`: non-consuming `resolvePsk`, `completePskProof` / `redeemBearer`, live-reuse termination, `KeyReuseReport`, and `beginPskArrival` (`D72` `compositionSettled`)
 * - `CIss4`: `verifyRedeemed` dual `redemptionId` + exact `lifecycle` lookup and 4-condition `sweepLeases()` reclamation
 */
import { verifyCredential, type RedeemedAdmissionVerifyInput, type RedeemedAdmissionVerifyResult } from "@apnex/caller-identity";
import { observePromises, readPlainJson } from "@apnex/shape-check";
import { defaultClock, defaultRandomBytes, defaultWallClock, type ClockPort, type WallClockPort } from "./clock-adapter.js";
import type {
	AdmissionHandoffCallbacks,
	AdmissionKeyProofMode,
	AdmissionUse,
	AdmissionUseControl,
	AdmissionUseObservation,
	AdmissionUsePool,
	BeginPskArrivalResult,
	CredentialIssuer,
	CredentialIssuerOptions,
	CredentialRedeemer,
	CredentialVerifier,
	IssueAdmissionKeyRequest,
	IssueAdmissionKeyResult,
	KeyReuseReport,
	ListStandingCodesRequest,
	ListStandingCodesResult,
	MintStandingCodeRequest,
	MintStandingCodeResult,
	NativePskProofAttempt,
	PublicStandingCodeRecord,
	ResolvePskResult,
	RevokeStandingCodeRequest,
	RevokeStandingCodeResult,
	StandingCodeRecord,
	StandingCodeStore,
} from "./issuer-types.js";
import {
	bytesToHex,
	isValidBoundedIdentifier,
	isValidIdentity,
	isValidIssuer,
	isValidPrintableAsciiPskIdentity,
	parseNodeId,
	readExactUint8Array,
	sha256Hex,
	utf8Bytes,
} from "./sha256.js";
import { createMemoryStandingCodeStore, readStandingCodeRecordList } from "./standing-code-store.js";

interface InternalUseSlot {
	readonly useId: string;
	readonly redemptionId: string;
	readonly generation: string;
	readonly issuer: string;
	readonly principal: string;
	readonly hub: string;
	readonly node: string;
	readonly instanceBinding: string;
	readonly validBeforeMonotonicMs: number;
	readonly lifecycle: AdmissionUseObservation;
	readonly control: AdmissionUseControl;
	state: "prepared" | "committed" | "uncertain";
	terminalObservedAtMs: number | null;
	sessionId: string | null;
	compacted: boolean;
}

interface InternalKeyRecord {
	readonly redemptionId: string;
	readonly generation: string;
	readonly secret: Uint8Array;
	readonly secretHex: string;
	readonly bearerToken: string;
	readonly keyFingerprint: string;
	readonly proofMode: AdmissionKeyProofMode;
	readonly issuer: string;
	readonly principal: string;
	readonly hub: string;
	readonly node: string;
	readonly instanceBinding: string;
	readonly issuedAtMonotonicMs: number;
	readonly validBeforeMonotonicMs: number;
	readonly retainUntilMonotonicMs: number;
	state: "unspent" | "preparing" | "spent" | "uncertain";
	reservationHeld: boolean;
	firstUse: InternalUseSlot | null;
	firstUseSummary: { readonly useId: string; readonly sessionId: string | null } | null;
	readonly committedLifecycles: WeakSet<object>;
	readonly uncertainLifecycles: WeakSet<object>;
	readonly refusedReuseLifecycles: WeakSet<object>;
}

interface InternalNodeLease {
	readonly hub: string;
	readonly node: string;
	readonly issuer: string;
	readonly principal: string;
	readonly instanceBinding: string;
	readonly continuationSecretHash: string;
	lastActivityMs: number;
	reservedHandles: number;
	readonly keys: Map<string, InternalKeyRecord>;
	readonly slots: Map<object, InternalUseSlot>;
}

const EXPLICIT_REDEMPTION_REFUSAL_REASONS = new Set([
	"authorization-expired",
	"expired",
	"invalid-authorization",
	"invalid-redemption",
	"inactive",
	"capacity",
	"already-recorded",
]);

/** Invokes a void callback and observes any returned or thrown native promises (`D54`, `D55`, `F4`). */
function callVoidHook(fn: () => unknown): void {
	try {
		const ret = fn();
		observePromises(ret);
	} catch (error) {
		observePromises(error);
	}
}

function validateVerifiersAtConstruction(verifiers: unknown): readonly CredentialVerifier[] {
	if (!Array.isArray(verifiers)) {
		throw new TypeError("verifiers must be an array of plain CredentialVerifier objects");
	}
	const out: CredentialVerifier[] = [];
	for (const entry of verifiers) {
		if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
			throw new TypeError("each CredentialVerifier must be a plain object with issuer and verify");
		}
		const proto = Object.getPrototypeOf(entry);
		if (proto !== Object.prototype && proto !== null) {
			throw new TypeError("each CredentialVerifier must be a plain object (Object.prototype or null prototype)");
		}
		if (Object.getOwnPropertySymbols(entry).length > 0) {
			throw new TypeError("each CredentialVerifier must have no symbol properties");
		}
		const names = Object.getOwnPropertyNames(entry);
		if (names.length !== 2) {
			throw new TypeError("each CredentialVerifier must have exactly own data properties issuer and verify");
		}
		const issuerDesc = Object.getOwnPropertyDescriptor(entry, "issuer");
		const verifyDesc = Object.getOwnPropertyDescriptor(entry, "verify");
		if (
			issuerDesc === undefined ||
			verifyDesc === undefined ||
			!issuerDesc.enumerable ||
			!verifyDesc.enumerable ||
			!Object.hasOwn(issuerDesc, "value") ||
			!Object.hasOwn(verifyDesc, "value") ||
			!isValidIssuer(issuerDesc.value) ||
			typeof verifyDesc.value !== "function"
		) {
			throw new TypeError("each CredentialVerifier must have own enumerable data properties issuer and verify");
		}
		out.push(
			Object.freeze({
				issuer: issuerDesc.value,
				verify: verifyDesc.value as CredentialVerifier["verify"],
			}),
		);
	}
	return Object.freeze(out);
}

function validatePositiveFinite(value: unknown, name: string, defaultValue: number): number {
	if (value === undefined) return defaultValue;
	if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
		throw new TypeError(`${name} must be a positive finite number`);
	}
	return value;
}

function validateNonNegativeFinite(value: unknown, name: string, defaultValue: number): number {
	if (value === undefined) return defaultValue;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
		throw new TypeError(`${name} must be a non-negative finite number`);
	}
	return value;
}

function validatePositiveInteger(value: unknown, name: string, defaultValue: number): number {
	if (value === undefined) return defaultValue;
	if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
		throw new TypeError(`${name} must be a positive integer`);
	}
	return value;
}

/** Awaits a native `Promise` via `Promise.prototype.then`, or returns synchronously; never invokes non-native thenables (`D54`, `D55`). */
async function settleNativePromiseOrValue(raw: unknown): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false }> {
	let native = false;
	try {
		native = raw instanceof Promise;
	} catch (error) {
		observePromises(error);
		observePromises(raw);
		return { ok: false };
	}
	if (!native) {
		return { ok: true, value: raw };
	}
	return new Promise((resolve) => {
		try {
			Reflect.apply(Promise.prototype.then, raw, [
				(value: unknown) => resolve({ ok: true, value }),
				(error: unknown) => {
					observePromises(error);
					resolve({ ok: false });
				},
			]);
		} catch (error) {
			observePromises(error);
			observePromises(raw);
			resolve({ ok: false });
		}
	});
}

/** Calls a boolean host callback and reads its result as a plain boolean through `readPlainJson` and `observePromises` (`D54`, `D55`). */
async function callBooleanRule(fn: () => unknown): Promise<{ readonly ok: true; readonly value: boolean } | { readonly ok: false }> {
	let raw: unknown;
	try {
		raw = fn();
	} catch (error) {
		observePromises(error);
		return { ok: false };
	}
	const settled = await settleNativePromiseOrValue(raw);
	if (!settled.ok) return { ok: false };
	const plain = readPlainJson(settled.value);
	if (!plain.ok || typeof plain.value !== "boolean") return { ok: false };
	return { ok: true, value: plain.value };
}

/**
 * Reads `AdmissionRedemptionPort.recordAdmissionRedemption`'s return value (`F1`, `F3`, `D54`, `D55`), reading
 * each own property descriptor at most once and accepting both AGP's `{ kind: "recorded", context: { redemptionId, lifecycle } }`
 * (preserving exact `lifecycle` capability identity without JSON-serializing its methods) and `{ kind: "recorded" }`,
 * as well as AGP's `{ kind: "refused", reason }` and shorthand `{ kind: <reason> }`.
 */
function readRedemptionOutcome(
	raw: unknown,
	expectedRedemptionId: string,
	expectedLifecycle: AdmissionUseObservation,
): { readonly outcome: "recorded" } | { readonly outcome: "explicit-refusal"; readonly reason: string } | { readonly outcome: "uncertain" } {
	const capturedValues: unknown[] = [];
	let rawEnumerated = false;
	const failUncertain = (): { readonly outcome: "uncertain" } => {
		if (!rawEnumerated) {
			observePromises(raw);
		}
		for (const item of capturedValues) observePromises(item);
		return { outcome: "uncertain" };
	};
	try {
		if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
			return failUncertain();
		}
		const proto = Object.getPrototypeOf(raw);
		if (proto !== Object.prototype && proto !== null) {
			return failUncertain();
		}
		if (Object.getOwnPropertySymbols(raw).length > 0) {
			return failUncertain();
		}
		const names = Object.getOwnPropertyNames(raw);
		const props = new Map<string, unknown>();
		for (const name of names) {
			const desc = Object.getOwnPropertyDescriptor(raw, name);
			if (desc !== undefined && Object.hasOwn(desc, "value")) {
				capturedValues.push(desc.value);
			}
			if (desc === undefined || !desc.enumerable || !Object.hasOwn(desc, "value")) {
				return failUncertain();
			}
			props.set(name, desc.value);
		}
		rawEnumerated = true;
		const kind = props.get("kind");
		if (typeof kind !== "string") {
			return failUncertain();
		}

		if (kind === "recorded") {
			if (names.length === 1) {
				return { outcome: "recorded" };
			}
			if (names.length === 2 && props.has("context")) {
				const ctx = props.get("context");
				if (typeof ctx !== "object" || ctx === null || Array.isArray(ctx)) return failUncertain();
				const ctxProto = Object.getPrototypeOf(ctx);
				if (ctxProto !== Object.prototype && ctxProto !== null) return failUncertain();
				if (Object.getOwnPropertySymbols(ctx).length > 0) return failUncertain();
				const ctxNames = Object.getOwnPropertyNames(ctx);
				if (ctxNames.length !== 2) return failUncertain();
				const ctxProps = new Map<string, unknown>();
				for (const ck of ctxNames) {
					const d = Object.getOwnPropertyDescriptor(ctx, ck);
					if (d !== undefined && Object.hasOwn(d, "value")) capturedValues.push(d.value);
					if (d === undefined || !d.enumerable || !Object.hasOwn(d, "value")) return failUncertain();
					ctxProps.set(ck, d.value);
				}
				if (
					ctxProps.get("redemptionId") !== expectedRedemptionId ||
					ctxProps.get("lifecycle") !== expectedLifecycle
				) {
					return failUncertain();
				}
				return { outcome: "recorded" };
			}
			return failUncertain();
		}

		if (kind === "refused" && names.length === 2 && props.has("reason")) {
			const reason = props.get("reason");
			if (typeof reason === "string" && EXPLICIT_REDEMPTION_REFUSAL_REASONS.has(reason)) {
				return { outcome: "explicit-refusal", reason };
			}
			return failUncertain();
		}

		if (names.length === 1 && EXPLICIT_REDEMPTION_REFUSAL_REASONS.has(kind)) {
			return { outcome: "explicit-refusal", reason: kind };
		}

		return failUncertain();
	} catch (error) {
		capturedValues.push(error);
		return failUncertain();
	}
}

/** Validates an AGP `AdmissionSessionIdentity` plain object and extracts `localSessionId` (`F1`). */
function extractSessionIdFromIdentity(sessionObj: unknown): string | "invalid" {
	if (typeof sessionObj !== "object" || sessionObj === null || Array.isArray(sessionObj)) return "invalid";
	const rec = sessionObj as Record<string, unknown>;
	for (const k of Object.keys(rec)) {
		if (k !== "remoteNodeId" && k !== "localSessionId" && k !== "authorizationAssociation") {
			return "invalid";
		}
	}
	if (!isValidBoundedIdentifier(rec.remoteNodeId) || !isValidBoundedIdentifier(rec.localSessionId)) {
		return "invalid";
	}
	if ("authorizationAssociation" in rec && rec.authorizationAssociation !== undefined) {
		const assoc = rec.authorizationAssociation;
		if (typeof assoc !== "object" || assoc === null || Array.isArray(assoc)) return "invalid";
		const assocRec = assoc as Record<string, unknown>;
		const assocKeys = Object.keys(assocRec);
		if (assocRec.mode === "unauthenticated") {
			if (assocKeys.length !== 1) return "invalid";
		} else if (assocRec.mode === "authenticated") {
			if (
				assocKeys.length !== 4 ||
				!isValidIssuer(assocRec.issuer) ||
				!isValidBoundedIdentifier(assocRec.principal) ||
				!isValidBoundedIdentifier(assocRec.instanceBinding)
			) {
				return "invalid";
			}
		} else {
			return "invalid";
		}
	}
	return rec.localSessionId;
}

/** Creates one `CredentialIssuer` instance for one hub audience (`CIss1` to `CIss4`). */
export function createCredentialIssuer(options: CredentialIssuerOptions): CredentialIssuer {
	if (typeof options !== "object" || options === null) {
		throw new TypeError("createCredentialIssuer requires an options object");
	}
	const hub = options.hub;
	if (!isValidBoundedIdentifier(hub)) {
		throw new TypeError("options.hub must be a valid bounded identifier string (1..256 Unicode scalar values)");
	}
	const verifiers = validateVerifiersAtConstruction(options.verifiers);
	const clock: ClockPort = options.clock ?? defaultClock;
	if (typeof clock !== "object" || clock === null || typeof clock.now !== "function" || typeof clock.schedule !== "function") {
		throw new TypeError("options.clock must be a ClockPort with now() and schedule(delayMs, callback)");
	}
	const wallClock: WallClockPort = options.wallClock ?? defaultWallClock;
	if (typeof wallClock !== "object" || wallClock === null || typeof wallClock.nowMs !== "function") {
		throw new TypeError("options.wallClock must have nowMs()");
	}
	const randomBytesFn = options.randomBytes ?? defaultRandomBytes;
	if (typeof randomBytesFn !== "function") {
		throw new TypeError("options.randomBytes must be a function (byteLength: number) => Uint8Array");
	}
	const drawRandomBytes = (byteLength: number): Uint8Array => {
		const rawBytes = randomBytesFn(byteLength);
		const copied = readExactUint8Array(rawBytes, byteLength);
		if (copied === null) {
			observePromises(rawBytes);
			throw new TypeError(`randomBytes(${byteLength}) must return a genuine Uint8Array of exact byteLength ${byteLength}`);
		}
		return copied;
	};

	const standingCodeStore: StandingCodeStore = options.standingCodeStore ?? createMemoryStandingCodeStore();
	if (
		typeof standingCodeStore !== "object" ||
		standingCodeStore === null ||
		typeof standingCodeStore.load !== "function" ||
		typeof standingCodeStore.save !== "function"
	) {
		throw new TypeError("options.standingCodeStore must have load() and save(records)");
	}
	const allowStandingCode = options.allowStandingCode ?? (({ minterPrincipal, identity }) => minterPrincipal === identity);
	if (typeof allowStandingCode !== "function") {
		throw new TypeError("options.allowStandingCode must be a function");
	}
	const allowAdmissionKey = options.allowAdmissionKey ?? (() => true);
	if (typeof allowAdmissionKey !== "function") {
		throw new TypeError("options.allowAdmissionKey must be a function");
	}
	const isSignInRevoked = options.isSignInRevoked;
	if (isSignInRevoked !== undefined && typeof isSignInRevoked !== "function") {
		throw new TypeError("options.isSignInRevoked must be a function when supplied");
	}
	const onKeyReuse = options.onKeyReuse;
	if (onKeyReuse !== undefined && typeof onKeyReuse !== "function") {
		throw new TypeError("options.onKeyReuse must be a function when supplied");
	}

	const keyLifetimeMs = validatePositiveFinite(options.keyLifetimeMs, "options.keyLifetimeMs", 60_000);
	const keyRetentionMs = validatePositiveFinite(options.keyRetentionMs, "options.keyRetentionMs", Math.max(120_000, keyLifetimeMs));
	if (keyRetentionMs < keyLifetimeMs) {
		throw new TypeError("options.keyRetentionMs must be >= options.keyLifetimeMs");
	}
	const reconnectGraceMs = validateNonNegativeFinite(options.reconnectGraceMs, "options.reconnectGraceMs", 60_000);
	const maxActiveLeases = validatePositiveInteger(options.maxActiveLeases, "options.maxActiveLeases", 1_024);
	const maxHandlesPerLease = validatePositiveInteger(options.maxHandlesPerLease, "options.maxHandlesPerLease", 16);
	const maxTotalHandles = validatePositiveInteger(options.maxTotalHandles, "options.maxTotalHandles", 4_096);
	const maxRetainedKeys = validatePositiveInteger(options.maxRetainedKeys, "options.maxRetainedKeys", maxTotalHandles);
	const maxPskIdentityBytes = validatePositiveInteger(options.maxPskIdentityBytes, "options.maxPskIdentityBytes", 127);
	if (maxPskIdentityBytes > 127) {
		throw new TypeError("options.maxPskIdentityBytes must be <= 127");
	}

	// Load and validate initial standing codes synchronously through readPlainJson (F2).
	let rawInitialCodes: unknown;
	try {
		rawInitialCodes = standingCodeStore.load();
	} catch (error) {
		observePromises(error);
		throw error;
	}
	const loadedCodes = readStandingCodeRecordList(rawInitialCodes);
	if (loadedCodes === null) {
		const err = new Error("standingCodeStore.load() returned invalid StandingCodeRecord data") as Error & { code: string };
		err.code = "code-store-corrupt";
		throw err;
	}

	const generation = `g${bytesToHex(drawRandomBytes(8)).slice(0, 15)}`;
	const codesById = new Map<string, StandingCodeRecord>();
	const codesByHash = new Map<string, StandingCodeRecord>();
	for (const rec of loadedCodes) {
		codesById.set(rec.codeId, rec);
		codesByHash.set(rec.codeHash, rec);
	}
	let storeQuarantined = false;

	const activeLeases = new Map<string, InternalNodeLease>();
	const retainedKeys = new Map<string, InternalKeyRecord>();
	const bearerTokensToKeyId = new Map<string, string>();
	const slotsByLifecycle = new Map<object, InternalUseSlot>();
	const attemptLookups = new WeakMap<object, Map<string, { readonly secret: Uint8Array; readonly lookupRef: object; readonly key: InternalKeyRecord }>>();
	const lookupRefToKey = new WeakMap<object, { readonly arrival: object | undefined; readonly key: InternalKeyRecord }>();

	let totalReservedHandles = 0;
	let nextAllocationId = 0;
	let nextKeyId = 0;
	let nextUseId = 0;

	const leaseKey = (h: string, n: string): string => `${h}\u0000${n}`;

	const isIssuedAdmissionKeyValue = (val: unknown): boolean => {
		if (typeof val === "string") {
			if (val.startsWith("ci_key_") || retainedKeys.has(val) || bearerTokensToKeyId.has(val)) {
				return true;
			}
			return false;
		}
		if (typeof val === "object" && val !== null) {
			try {
				const desc = Object.getOwnPropertyDescriptor(val, "redemptionId");
				const pskDesc = Object.getOwnPropertyDescriptor(val, "pskIdentity");
				const bearerDesc = Object.getOwnPropertyDescriptor(val, "bearerToken");
				if (
					(desc !== undefined && Object.hasOwn(desc, "value") && typeof desc.value === "string" && retainedKeys.has(desc.value)) ||
					(pskDesc !== undefined && Object.hasOwn(pskDesc, "value") && typeof pskDesc.value === "string" && retainedKeys.has(pskDesc.value)) ||
					(bearerDesc !== undefined && Object.hasOwn(bearerDesc, "value") && typeof bearerDesc.value === "string" && (bearerDesc.value.startsWith("ci_key_") || bearerTokensToKeyId.has(bearerDesc.value)))
				) {
					return true;
				}
			} catch (err) {
				observePromises(err);
			}
		}
		return false;
	};

	const isStandingCodeValue = (val: unknown): boolean => {
		if (typeof val === "string") {
			if (val.startsWith("ci_code_")) return true;
			const hash = sha256Hex(val);
			if (codesByHash.has(hash)) return true;
		}
		return false;
	};

	const checkSignInRevoked = async (principal: string, issuer: string, session: string | null): Promise<boolean> => {
		if (isSignInRevoked === undefined) return false;
		const res = await callBooleanRule(() => isSignInRevoked(Object.freeze({ principal, issuer, session })));
		if (!res.ok) return true;
		return res.value;
	};

	const releaseKeyReservation = (lease: InternalNodeLease | undefined, key: InternalKeyRecord): void => {
		if (!key.reservationHeld) return;
		key.reservationHeld = false;
		if (lease !== undefined && lease.reservedHandles > 0) {
			lease.reservedHandles -= 1;
		}
		if (totalReservedHandles > 0) {
			totalReservedHandles -= 1;
		}
	};

	/**
	 * Reads `lifecycle.readAdmissionUse()` as plain data (`F1`, `D54`, `D55`), supporting both AGP's
	 * `AdmissionUseSnapshot` (`session.localSessionId`, `admittedSession.localSessionId`, `reachedEstablished`)
	 * and shorthand `{ state, sessionId }`.
	 */
	const readUseObservation = (
		lifecycle: AdmissionUseObservation,
	): { readonly state: "pending" | "admitted" | "established" | "terminal"; readonly sessionId: string | null } | "unknown" => {
		let raw: unknown;
		try {
			raw = lifecycle.readAdmissionUse();
		} catch (error) {
			observePromises(error);
			return "unknown";
		}
		const plain = readPlainJson(raw);
		if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
			return "unknown";
		}
		const obj = plain.value as Record<string, unknown>;
		const state = obj.state;
		if (state !== "pending" && state !== "admitted" && state !== "established" && state !== "terminal") {
			return "unknown";
		}
		for (const k of Object.keys(obj)) {
			if (
				k !== "state" &&
				k !== "session" &&
				k !== "admittedSession" &&
				k !== "reachedEstablished" &&
				k !== "sessionId"
			) {
				return "unknown";
			}
		}

		let sessionId: string | null = null;
		if ("sessionId" in obj && obj.sessionId !== undefined && obj.sessionId !== null) {
			if (!isValidBoundedIdentifier(obj.sessionId)) return "unknown";
			sessionId = obj.sessionId;
		}
		if ("session" in obj) {
			if (state !== "admitted" && state !== "established") return "unknown";
			const extracted = extractSessionIdFromIdentity(obj.session);
			if (extracted === "invalid") return "unknown";
			sessionId = extracted;
		}
		let hasValidAdmittedSession = false;
		if ("admittedSession" in obj) {
			if (state !== "terminal") return "unknown";
			const extracted = extractSessionIdFromIdentity(obj.admittedSession);
			if (extracted === "invalid") return "unknown";
			hasValidAdmittedSession = true;
			sessionId = extracted;
		}
		if ("reachedEstablished" in obj) {
			if (state !== "terminal" || typeof obj.reachedEstablished !== "boolean") return "unknown";
			if (obj.reachedEstablished === true && !hasValidAdmittedSession) {
				return "unknown";
			}
		}

		return { state, sessionId };
	};

	const sweepLeases = (): void => {
		for (const [lKey, lease] of activeLeases) {
			// 1. Poll all slots on the lease, sampling the clock AFTER each readUseObservation completes (F2).
			for (const [lc, slot] of lease.slots) {
				const obs = readUseObservation(slot.lifecycle);
				const obsNowMs = clock.now();
				const keyRec = retainedKeys.get(slot.redemptionId);
				if (obs !== "unknown") {
					if (obs.sessionId !== null) {
						slot.sessionId = obs.sessionId;
						if (keyRec !== undefined && keyRec.firstUse === slot) {
							keyRec.firstUseSummary = Object.freeze({ useId: slot.useId, sessionId: obs.sessionId });
						}
					}
					if (obs.state === "terminal") {
						if (slot.terminalObservedAtMs === null) {
							slot.terminalObservedAtMs = obsNowMs;
							lease.lastActivityMs = Math.max(lease.lastActivityMs, obsNowMs);
						}
						if (obsNowMs >= slot.validBeforeMonotonicMs) {
							slot.compacted = true;
							lease.slots.delete(lc);
							slotsByLifecycle.delete(lc);
							if (keyRec !== undefined) {
								if (keyRec.firstUse === slot) {
									keyRec.firstUseSummary = Object.freeze({
										useId: slot.useId,
										sessionId: slot.sessionId,
									});
									keyRec.firstUse = null;
								}
								releaseKeyReservation(lease, keyRec);
							}
						}
					}
				}
			}

			const leaseNowMs = clock.now();
			// 2. Release reservations for unspent expired keys on this lease.
			for (const [, keyRec] of lease.keys) {
				if (keyRec.state === "unspent" && leaseNowMs >= keyRec.validBeforeMonotonicMs) {
					releaseKeyReservation(lease, keyRec);
				}
				if (
					leaseNowMs >= keyRec.retainUntilMonotonicMs &&
					keyRec.firstUse === null &&
					!keyRec.reservationHeld
				) {
					lease.keys.delete(keyRec.redemptionId);
					retainedKeys.delete(keyRec.redemptionId);
					bearerTokensToKeyId.delete(keyRec.bearerToken);
				}
			}

			// 3. Check the 4 D62 reclamation conditions together in the same synchronous turn:
			let hasLiveUnspentKey = false;
			for (const [, keyRec] of lease.keys) {
				if ((keyRec.state === "unspent" || keyRec.state === "preparing") && leaseNowMs < keyRec.validBeforeMonotonicMs) {
					hasLiveUnspentKey = true;
					break;
				}
			}
			let hasNonTerminalSlot = false;
			for (const [, slot] of lease.slots) {
				if (slot.terminalObservedAtMs === null) {
					hasNonTerminalSlot = true;
					break;
				}
			}
			const graceElapsed = leaseNowMs - lease.lastActivityMs >= reconnectGraceMs;

			if (!hasLiveUnspentKey && !hasNonTerminalSlot && graceElapsed) {
				for (const [lc, slot] of lease.slots) {
					slot.compacted = true;
					slotsByLifecycle.delete(lc);
					const keyRec = retainedKeys.get(slot.redemptionId);
					if (keyRec !== undefined) {
						if (keyRec.firstUse === slot) {
							keyRec.firstUseSummary = Object.freeze({
								useId: slot.useId,
								sessionId: slot.sessionId,
							});
							keyRec.firstUse = null;
						}
						releaseKeyReservation(lease, keyRec);
					}
				}
				lease.slots.clear();
				activeLeases.delete(lKey);
			}
		}

		// 4. Clean up any orphaned retained keys past retainUntilMonotonicMs whose lease was already reclaimed.
		const finalNowMs = clock.now();
		for (const [redemptionId, keyRec] of retainedKeys) {
			if (finalNowMs >= keyRec.validBeforeMonotonicMs && keyRec.state === "unspent" && keyRec.reservationHeld) {
				const lease = activeLeases.get(leaseKey(keyRec.hub, keyRec.node));
				releaseKeyReservation(lease, keyRec);
			}
			if (finalNowMs >= keyRec.retainUntilMonotonicMs && keyRec.firstUse === null && !keyRec.reservationHeld) {
				retainedKeys.delete(redemptionId);
				bearerTokensToKeyId.delete(keyRec.bearerToken);
			}
		}
	};

	const saveStandingCodes = (nextRecords: readonly StandingCodeRecord[]): "ok" | "unwritable" => {
		try {
			standingCodeStore.save(nextRecords);
			return "ok";
		} catch (error) {
			// Inspect own descriptors of `error` in a single pass so `afterRename` is read at most once (Attempt 4 F1).
			if (typeof error === "object" && error !== null) {
				let isPromise = false;
				try {
					isPromise = error instanceof Promise;
				} catch (instErr) {
					observePromises(instErr);
				}
				if (isPromise) {
					observePromises(error);
					return "unwritable";
				}
				const capturedErrorValues: unknown[] = [];
				try {
					for (const name of Object.getOwnPropertyNames(error)) {
						const desc = Object.getOwnPropertyDescriptor(error, name);
						if (desc !== undefined && Object.hasOwn(desc, "value")) {
							capturedErrorValues.push(desc.value);
							if (name === "afterRename" && desc.enumerable === true && desc.value === true) {
								storeQuarantined = true;
							}
						}
					}
				} catch (descErr) {
					capturedErrorValues.push(descErr);
				}
				for (const item of capturedErrorValues) observePromises(item);
			}
			return "unwritable";
		}
	};

	const mintStandingCode = async (request: MintStandingCodeRequest): Promise<MintStandingCodeResult> => {
		if (typeof request !== "object" || request === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		const { proof, identity, expiresAtMs } = request;
		if (isIssuedAdmissionKeyValue(proof) || isStandingCodeValue(proof)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		const verified = await verifyCredential(verifiers, proof, { clock });
		if (verified === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (await checkSignInRevoked(verified.principal, verified.issuer, verified.session)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (!isValidIdentity(identity)) {
			return Object.freeze({ ok: false, code: "invalid-identity" });
		}
		const nowWall = wallClock.nowMs();
		if (expiresAtMs !== undefined && expiresAtMs !== null) {
			if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs) || expiresAtMs <= nowWall) {
				return Object.freeze({ ok: false, code: "invalid-expiry" });
			}
		}
		const allowed = await callBooleanRule(() =>
			allowStandingCode(
				Object.freeze({
					minterPrincipal: verified.principal,
					minterIssuer: verified.issuer,
					identity,
				}),
			),
		);
		if (!allowed.ok || !allowed.value) {
			return Object.freeze({ ok: false, code: "forbidden-identity" });
		}

		// Serialized commit turn: re-verify sign-in expiry, revocation, post-await expiry, quarantine, and wall-clock expiry (F3).
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (await checkSignInRevoked(verified.principal, verified.issuer, verified.session)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		const codeSecretBytes = drawRandomBytes(32);
		const codeIdBytes = drawRandomBytes(8);
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		const commitWall = wallClock.nowMs();
		if (expiresAtMs !== undefined && expiresAtMs !== null && expiresAtMs <= commitWall) {
			return Object.freeze({ ok: false, code: "invalid-expiry" });
		}

		const code = `ci_code_${bytesToHex(codeSecretBytes)}`;
		const codeId = `sc_${bytesToHex(codeIdBytes)}`;
		const codeHash = sha256Hex(code);
		const record: StandingCodeRecord = Object.freeze({
			codeId,
			codeHash,
			identity,
			minterPrincipal: verified.principal,
			minterIssuer: verified.issuer,
			createdAtMs: commitWall,
			expiresAtMs: expiresAtMs ?? null,
			revokedAtMs: null,
		});
		const nextList = Object.freeze([...codesById.values(), record]);
		if (saveStandingCodes(nextList) !== "ok") {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		codesById.set(codeId, record);
		codesByHash.set(codeHash, record);
		return Object.freeze({
			ok: true,
			codeId,
			code,
			identity,
			minterPrincipal: verified.principal,
			minterIssuer: verified.issuer,
			createdAtMs: commitWall,
			expiresAtMs: expiresAtMs ?? null,
		});
	};

	const listStandingCodes = async (request: ListStandingCodesRequest): Promise<ListStandingCodesResult> => {
		if (typeof request !== "object" || request === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		const { proof } = request;
		if (isIssuedAdmissionKeyValue(proof) || isStandingCodeValue(proof)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		const verified = await verifyCredential(verifiers, proof, { clock });
		if (verified === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (await checkSignInRevoked(verified.principal, verified.issuer, verified.session)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		const codes: PublicStandingCodeRecord[] = [];
		for (const rec of codesById.values()) {
			if (rec.minterPrincipal === verified.principal && rec.minterIssuer === verified.issuer) {
				codes.push(
					Object.freeze({
						codeId: rec.codeId,
						identity: rec.identity,
						minterPrincipal: rec.minterPrincipal,
						minterIssuer: rec.minterIssuer,
						createdAtMs: rec.createdAtMs,
						expiresAtMs: rec.expiresAtMs,
						revokedAtMs: rec.revokedAtMs,
					}),
				);
			}
		}
		return Object.freeze({ ok: true, codes: Object.freeze(codes) });
	};

	const revokeStandingCode = async (request: RevokeStandingCodeRequest): Promise<RevokeStandingCodeResult> => {
		if (typeof request !== "object" || request === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		const { proof, codeId } = request;
		if (isIssuedAdmissionKeyValue(proof) || isStandingCodeValue(proof)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		const verified = await verifyCredential(verifiers, proof, { clock });
		if (verified === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (await checkSignInRevoked(verified.principal, verified.issuer, verified.session)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (storeQuarantined) {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		if (!isValidBoundedIdentifier(codeId)) {
			return Object.freeze({ ok: false, code: "not-found" });
		}
		const existing = codesById.get(codeId);
		if (
			existing === undefined ||
			existing.minterPrincipal !== verified.principal ||
			existing.minterIssuer !== verified.issuer
		) {
			return Object.freeze({ ok: false, code: "not-found" });
		}
		const revokedAtMs = existing.revokedAtMs ?? wallClock.nowMs();
		const updated: StandingCodeRecord = Object.freeze({
			...existing,
			revokedAtMs,
		});
		const nextList: StandingCodeRecord[] = [];
		for (const rec of codesById.values()) {
			nextList.push(rec.codeId === codeId ? updated : rec);
		}
		if (saveStandingCodes(Object.freeze(nextList)) !== "ok") {
			return Object.freeze({ ok: false, code: "code-store-unwritable" });
		}
		codesById.set(codeId, updated);
		codesByHash.set(updated.codeHash, updated);
		return Object.freeze({ ok: true, codeId, revokedAtMs });
	};

	const issueAdmissionKey = async (request: IssueAdmissionKeyRequest): Promise<IssueAdmissionKeyResult> => {
		if (typeof request !== "object" || request === null) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}
		if (!isValidBoundedIdentifier(request.hub) || request.hub !== hub) {
			return Object.freeze({ ok: false, code: "wrong-hub" });
		}
		const parsedNode = parseNodeId(request.node);
		if (parsedNode === null) {
			return Object.freeze({ ok: false, code: "invalid-node" });
		}
		const proofMode: AdmissionKeyProofMode = request.proofMode ?? "native-tls13-external-psk-v1";
		if (proofMode !== "native-tls13-external-psk-v1" && proofMode !== "bearer") {
			return Object.freeze({ ok: false, code: "invalid-proof-mode" });
		}

		let proofKind: "sign-in" | "standing-code";
		let signInToken: unknown;
		let standingCodeSecret: string | undefined;

		if ("grantType" in request) {
			if (request.grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
				proofKind = "sign-in";
				signInToken = request.subjectToken;
			} else if (request.grantType === "client_credentials") {
				proofKind = "standing-code";
				standingCodeSecret = request.clientSecret;
			} else {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
		} else if ("proof" in request && typeof request.proof === "object" && request.proof !== null) {
			if (request.proof.kind === "sign-in") {
				proofKind = "sign-in";
				signInToken = request.proof.token;
			} else if (request.proof.kind === "standing-code") {
				proofKind = "standing-code";
				standingCodeSecret = request.proof.code;
			} else {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
		} else {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}

		let principal: string;
		let issuer: string;
		let verifiedSession: string | null = null;
		let verifiedExpiresAt: number | null = null;
		let codeHashForCommit: string | undefined;

		if (proofKind === "sign-in") {
			if (isIssuedAdmissionKeyValue(signInToken) || isStandingCodeValue(signInToken)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			const verified = await verifyCredential(verifiers, signInToken, { clock });
			if (verified === null) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			if (await checkSignInRevoked(verified.principal, verified.issuer, verified.session)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			if (verified.expiresAt !== null && !(clock.now() < verified.expiresAt)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			principal = verified.principal;
			issuer = verified.issuer;
			verifiedSession = verified.session;
			verifiedExpiresAt = verified.expiresAt;
		} else {
			if (storeQuarantined) {
				return Object.freeze({ ok: false, code: "code-store-unwritable" });
			}
			if (typeof standingCodeSecret !== "string" || isIssuedAdmissionKeyValue(standingCodeSecret)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			const codeHash = sha256Hex(standingCodeSecret);
			const rec = codesByHash.get(codeHash);
			const nowWall = wallClock.nowMs();
			if (
				rec === undefined ||
				rec.revokedAtMs !== null ||
				(rec.expiresAtMs !== null && nowWall >= rec.expiresAtMs) ||
				rec.identity !== parsedNode.identity
			) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			principal = rec.identity;
			issuer = rec.minterIssuer;
			codeHashForCommit = codeHash;
		}

		const allowed = await callBooleanRule(() =>
			allowAdmissionKey(
				Object.freeze({
					principal,
					issuer,
					hub,
					node: request.node,
					proofKind,
					proofMode,
				}),
			),
		);
		if (!allowed.ok || !allowed.value) {
			return Object.freeze({ ok: false, code: "policy-refused" });
		}

		// Serialized commit turn: sweep leases first, then re-verify proof liveness & revocation so any
		// revocation or clock advancement during sweepLeases() is caught before issuing a key (F5).
		sweepLeases();

		if (proofKind === "sign-in") {
			if (verifiedExpiresAt !== null && !(clock.now() < verifiedExpiresAt)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			if (await checkSignInRevoked(principal, issuer, verifiedSession)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			if (verifiedExpiresAt !== null && !(clock.now() < verifiedExpiresAt)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
		} else {
			if (storeQuarantined) {
				return Object.freeze({ ok: false, code: "code-store-unwritable" });
			}
			const recAfterSweep = codesByHash.get(codeHashForCommit!);
			const nowWallAfterSweep = wallClock.nowMs();
			if (
				recAfterSweep === undefined ||
				recAfterSweep.revokedAtMs !== null ||
				(recAfterSweep.expiresAtMs !== null && nowWallAfterSweep >= recAfterSweep.expiresAtMs) ||
				recAfterSweep.identity !== parsedNode.identity
			) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
		}

		const nowAtIssue = clock.now();
		if (proofKind === "sign-in" && verifiedExpiresAt !== null && !(nowAtIssue < verifiedExpiresAt)) {
			return Object.freeze({ ok: false, code: "proof-refused" });
		}

		if (retainedKeys.size >= maxRetainedKeys) {
			return Object.freeze({ ok: false, code: "lease-capacity" });
		}

		const candidateRedemptionId = `${generation}-${nextKeyId + 1}`;
		if (
			!isValidPrintableAsciiPskIdentity(candidateRedemptionId, maxPskIdentityBytes) ||
			utf8Bytes(candidateRedemptionId).byteLength > maxPskIdentityBytes
		) {
			return Object.freeze({ ok: false, code: "incompatible-psk-identity" });
		}

		const lKey = leaseKey(hub, request.node);
		let lease = activeLeases.get(lKey);
		let returnedContinuationSecret: string;

		if (lease !== undefined) {
			if (
				lease.issuer !== issuer ||
				lease.principal !== principal ||
				typeof request.continuationSecret !== "string" ||
				sha256Hex(request.continuationSecret) !== lease.continuationSecretHash
			) {
				return Object.freeze({ ok: false, code: "node-identity-conflict" });
			}
			if (lease.reservedHandles >= maxHandlesPerLease || totalReservedHandles >= maxTotalHandles) {
				return Object.freeze({ ok: false, code: "lease-capacity" });
			}
			const secretBytes = drawRandomBytes(32);
			const nowAtIssue = clock.now();
			if (proofKind === "sign-in" && verifiedExpiresAt !== null && !(nowAtIssue < verifiedExpiresAt)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			lease.lastActivityMs = Math.max(lease.lastActivityMs, nowAtIssue);
			returnedContinuationSecret = request.continuationSecret;
			return finishKeyIssuance(lease, secretBytes, nowAtIssue, returnedContinuationSecret);
		} else {
			if (activeLeases.size >= maxActiveLeases || totalReservedHandles >= maxTotalHandles) {
				return Object.freeze({ ok: false, code: "lease-capacity" });
			}
			const contBytes = drawRandomBytes(32);
			const secretBytes = drawRandomBytes(32);
			const nowAtIssue = clock.now();
			if (proofKind === "sign-in" && verifiedExpiresAt !== null && !(nowAtIssue < verifiedExpiresAt)) {
				return Object.freeze({ ok: false, code: "proof-refused" });
			}
			const freshContinuationSecret = `ci_cont_${bytesToHex(contBytes)}`;
			const continuationSecretHash = sha256Hex(freshContinuationSecret);
			const instanceBinding = `${generation}-${++nextAllocationId}`;
			lease = {
				hub,
				node: request.node,
				issuer,
				principal,
				instanceBinding,
				continuationSecretHash,
				lastActivityMs: nowAtIssue,
				reservedHandles: 0,
				keys: new Map(),
				slots: new Map(),
			};
			activeLeases.set(lKey, lease);
			returnedContinuationSecret = freshContinuationSecret;
			return finishKeyIssuance(lease, secretBytes, nowAtIssue, returnedContinuationSecret);
		}

		function finishKeyIssuance(
			targetLease: InternalNodeLease,
			secretBytes: Uint8Array,
			nowAtIssue: number,
			contSecret: string,
		): IssueAdmissionKeyResult {
			const secretHex = bytesToHex(secretBytes);
			const redemptionId = `${generation}-${++nextKeyId}`;
			const bearerToken = `ci_key_${redemptionId}_${secretHex}`;
			const keyFingerprint = sha256Hex(`${redemptionId}:${secretHex}`);
			const validBeforeMonotonicMs = nowAtIssue + keyLifetimeMs;
			const retainUntilMonotonicMs = nowAtIssue + keyRetentionMs;

			targetLease.reservedHandles += 1;
			totalReservedHandles += 1;

			const keyRec: InternalKeyRecord = {
				redemptionId,
				generation,
				secret: new Uint8Array(secretBytes),
				secretHex,
				bearerToken,
				keyFingerprint,
				proofMode,
				issuer,
				principal,
				hub,
				node: request.node,
				instanceBinding: targetLease.instanceBinding,
				issuedAtMonotonicMs: nowAtIssue,
				validBeforeMonotonicMs,
				retainUntilMonotonicMs,
				state: "unspent",
				reservationHeld: true,
				firstUse: null,
				firstUseSummary: null,
				committedLifecycles: new WeakSet(),
				uncertainLifecycles: new WeakSet(),
				refusedReuseLifecycles: new WeakSet(),
			};
			targetLease.keys.set(redemptionId, keyRec);
			retainedKeys.set(redemptionId, keyRec);
			bearerTokensToKeyId.set(bearerToken, redemptionId);

			const claims = Object.freeze({
				iss: issuer,
				sub: principal,
				aud: hub,
				client_id: request.node,
				jti: redemptionId,
				exp: Math.floor(validBeforeMonotonicMs / 1000),
			});

			return Object.freeze({
				ok: true,
				redemptionId,
				pskIdentity: redemptionId,
				secret: new Uint8Array(secretBytes),
				secretHex,
				bearerToken,
				proofMode,
				issuer,
				principal,
				hub,
				node: request.node,
				instanceBinding: targetLease.instanceBinding,
				continuationSecret: contSecret,
				issuedAtMonotonicMs: nowAtIssue,
				validBeforeMonotonicMs,
				claims,
			});
		}
	};

	const resolvePsk = (pskIdentity: string, attempt?: { readonly arrival?: object }): ResolvePskResult => {
		if (!isValidPrintableAsciiPskIdentity(pskIdentity, maxPskIdentityBytes)) {
			return Object.freeze({ kind: "unknown" });
		}
		const keyRec = retainedKeys.get(pskIdentity);
		if (keyRec === undefined) {
			return Object.freeze({ kind: "unknown" });
		}
		if (
			keyRec.generation !== generation ||
			keyRec.proofMode !== "native-tls13-external-psk-v1" ||
			keyRec.hub !== hub ||
			!(clock.now() < keyRec.retainUntilMonotonicMs)
		) {
			return Object.freeze({ kind: "unknown" });
		}
		const arrivalKey = attempt?.arrival ?? attempt;
		if (arrivalKey !== undefined && typeof arrivalKey === "object" && arrivalKey !== null) {
			let byId = attemptLookups.get(arrivalKey);
			if (byId === undefined) {
				byId = new Map();
				attemptLookups.set(arrivalKey, byId);
			}
			const existing = byId.get(pskIdentity);
			if (existing !== undefined) {
				return Object.freeze({
					kind: "resolved",
					secret: new Uint8Array(existing.secret),
					lookupRef: existing.lookupRef,
				});
			}
			const lookupRef = Object.freeze({ pskIdentity });
			const entry = { secret: keyRec.secret, lookupRef, key: keyRec };
			byId.set(pskIdentity, entry);
			lookupRefToKey.set(lookupRef, { arrival: arrivalKey, key: keyRec });
			return Object.freeze({
				kind: "resolved",
				secret: new Uint8Array(keyRec.secret),
				lookupRef,
			});
		}
		const lookupRef = Object.freeze({ pskIdentity });
		lookupRefToKey.set(lookupRef, { arrival: undefined, key: keyRec });
		return Object.freeze({
			kind: "resolved",
			secret: new Uint8Array(keyRec.secret),
			lookupRef,
		});
	};

	const executeRedemptionTransaction = (
		keyRec: InternalKeyRecord,
		use: AdmissionUse,
		remoteNodeId?: string,
	): "redeemed" | "refused" => {
		if (
			typeof use !== "object" ||
			use === null ||
			typeof use.lifecycle !== "object" ||
			use.lifecycle === null ||
			typeof use.control !== "object" ||
			use.control === null ||
			typeof use.control.requestAdmissionTermination !== "function" ||
			typeof use.redemption !== "object" ||
			use.redemption === null ||
			typeof use.redemption.recordAdmissionRedemption !== "function"
		) {
			return "refused";
		}

		// 1. Existing use.lifecycle registration check first (CIss3 step 1, o:F2, o:F4, F8).
		const existingSlot = slotsByLifecycle.get(use.lifecycle);
		if (existingSlot !== undefined) {
			if (existingSlot.redemptionId === keyRec.redemptionId) {
				return existingSlot.state === "committed" ? "redeemed" : "refused";
			}
			return "refused";
		}
		if (keyRec.committedLifecycles.has(use.lifecycle)) {
			return "redeemed";
		}
		if (keyRec.uncertainLifecycles.has(use.lifecycle) || keyRec.refusedReuseLifecycles.has(use.lifecycle)) {
			return "refused";
		}

		// 2. Second presentation / key reuse check (CIss3 step 2, o:F2, o:F3, o:F6, F1, F4, F6, Attempt 4 F2).
		if (keyRec.state === "preparing" || keyRec.state === "spent" || keyRec.state === "uncertain") {
			keyRec.refusedReuseLifecycles.add(use.lifecycle);
			const secondUseId = `${generation}-use-${++nextUseId}`;
			const firstUseSlot = keyRec.firstUse;
			const firstUseId = firstUseSlot?.useId ?? keyRec.firstUseSummary?.useId ?? `${generation}-use-0`;
			let firstSession: string | null = keyRec.firstUseSummary?.sessionId ?? null;
			if (firstUseSlot !== null) {
				const obs = readUseObservation(firstUseSlot.lifecycle);
				if (obs !== "unknown" && obs.sessionId !== null) {
					firstSession = obs.sessionId;
					firstUseSlot.sessionId = obs.sessionId;
					keyRec.firstUseSummary = Object.freeze({
						useId: firstUseSlot.useId,
						sessionId: obs.sessionId,
					});
				} else if (keyRec.firstUseSummary?.sessionId !== null && keyRec.firstUseSummary?.sessionId !== undefined) {
					firstSession = keyRec.firstUseSummary.sessionId;
				}
			}
			// Sample clock AFTER readUseObservation so an observation that crosses expiry never authorizes termination (F6).
			const nowMs = clock.now();
			const live = nowMs < keyRec.validBeforeMonotonicMs;
			let firstSessionStopped = false;
			if (live && firstUseSlot !== null) {
				const firstControl = firstUseSlot.control;
				callVoidHook(() => firstControl.requestAdmissionTermination());
				firstSessionStopped = true;
			}
			if (onKeyReuse !== undefined) {
				const report: KeyReuseReport = Object.freeze({
					keyFingerprint: keyRec.keyFingerprint,
					redemptionId: keyRec.redemptionId,
					principal: keyRec.principal,
					issuer: keyRec.issuer,
					hub: keyRec.hub,
					node: keyRec.node,
					firstUseId,
					secondUseId,
					firstSession,
					secondSession: null,
					firstRedemptionId: keyRec.redemptionId,
					secondRedemptionId: keyRec.redemptionId,
					firstSessionStopped,
				});
				callVoidHook(() => onKeyReuse(report));
			}
			return "refused";
		}

		// 3. First presentation (keyRec.state === "unspent", CIss3 step 3).
		if (keyRec.generation !== generation || keyRec.hub !== hub) {
			return "refused";
		}
		if (remoteNodeId !== undefined && remoteNodeId !== keyRec.node) {
			return "refused";
		}
		const lease = activeLeases.get(leaseKey(keyRec.hub, keyRec.node));
		if (lease === undefined || lease.instanceBinding !== keyRec.instanceBinding) {
			return "refused";
		}
		const nowBeforeRecord = clock.now();
		if (!(nowBeforeRecord < keyRec.validBeforeMonotonicMs)) {
			releaseKeyReservation(lease, keyRec);
			return "refused";
		}

		// Pre-insert slot in state "prepared" and transition keyRec.state to "preparing" BEFORE calling out,
		// so any synchronous reentrant redemption with a distinct lifecycle is caught as a second presentation (F1).
		const useId = `${generation}-use-${++nextUseId}`;
		const slot: InternalUseSlot = {
			useId,
			redemptionId: keyRec.redemptionId,
			generation,
			issuer: keyRec.issuer,
			principal: keyRec.principal,
			hub: keyRec.hub,
			node: keyRec.node,
			instanceBinding: keyRec.instanceBinding,
			validBeforeMonotonicMs: keyRec.validBeforeMonotonicMs,
			lifecycle: use.lifecycle,
			control: use.control,
			state: "prepared",
			terminalObservedAtMs: null,
			sessionId: null,
			compacted: false,
		};
		keyRec.state = "preparing";
		keyRec.firstUse = slot;
		keyRec.firstUseSummary = Object.freeze({ useId, sessionId: null });
		lease.slots.set(use.lifecycle, slot);
		slotsByLifecycle.set(use.lifecycle, slot);

		let rawResult: unknown;
		try {
			rawResult = use.redemption.recordAdmissionRedemption(
				keyRec.redemptionId,
				Object.freeze({
					clock,
					validBeforeMonotonicMs: keyRec.validBeforeMonotonicMs,
				}),
			);
		} catch (error) {
			observePromises(error);
			slot.state = "uncertain";
			keyRec.state = "uncertain";
			keyRec.uncertainLifecycles.add(use.lifecycle);
			keyRec.firstUse = slot;
			keyRec.firstUseSummary = Object.freeze({ useId, sessionId: null });
			callVoidHook(() => use.control.requestAdmissionTermination());
			return "refused";
		}

		const parsedOutcome = readRedemptionOutcome(rawResult, keyRec.redemptionId, use.lifecycle);
		if (parsedOutcome.outcome === "recorded") {
			slot.state = "committed";
			keyRec.state = "spent";
			keyRec.committedLifecycles.add(use.lifecycle);
			keyRec.firstUse = slot;
			const initialObs = readUseObservation(use.lifecycle);
			const initialSessionId = initialObs !== "unknown" ? initialObs.sessionId : null;
			slot.sessionId = initialSessionId;
			keyRec.firstUseSummary = Object.freeze({ useId, sessionId: initialSessionId });
			lease.lastActivityMs = Math.max(lease.lastActivityMs, clock.now());
			return "redeemed";
		}

		if (parsedOutcome.outcome === "explicit-refusal") {
			lease.slots.delete(use.lifecycle);
			slotsByLifecycle.delete(use.lifecycle);
			keyRec.state = "unspent";
			keyRec.firstUse = null;
			keyRec.firstUseSummary = null;
			if (parsedOutcome.reason === "expired" || parsedOutcome.reason === "authorization-expired") {
				if (clock.now() >= keyRec.validBeforeMonotonicMs) {
					releaseKeyReservation(lease, keyRec);
				}
			}
			return "refused";
		}

		slot.state = "uncertain";
		keyRec.state = "uncertain";
		keyRec.uncertainLifecycles.add(use.lifecycle);
		keyRec.firstUse = slot;
		keyRec.firstUseSummary = Object.freeze({ useId, sessionId: null });
		callVoidHook(() => use.control.requestAdmissionTermination());
		return "refused";
	};

	const completePskProof = (
		attempt: { readonly arrival: object; readonly use: AdmissionUse; readonly lookupRef?: object },
		proof: { readonly arrival: object; readonly lookupRef: object },
	): "redeemed" | "refused" => {
		if (
			typeof attempt !== "object" ||
			attempt === null ||
			typeof proof !== "object" ||
			proof === null ||
			typeof attempt.arrival !== "object" ||
			attempt.arrival === null ||
			proof.arrival !== attempt.arrival ||
			typeof proof.lookupRef !== "object" ||
			proof.lookupRef === null
		) {
			return "refused";
		}
		if (attempt.lookupRef !== undefined && proof.lookupRef !== attempt.lookupRef) {
			return "refused";
		}
		const found = lookupRefToKey.get(proof.lookupRef);
		if (found === undefined) {
			return "refused";
		}
		if (found.arrival !== undefined && found.arrival !== attempt.arrival) {
			return "refused";
		}
		return executeRedemptionTransaction(found.key, attempt.use);
	};

	const redeemBearer = (use: AdmissionUse, bearerToken: string, remoteNodeId?: string): "redeemed" | "refused" => {
		if (typeof bearerToken !== "string" || isStandingCodeValue(bearerToken)) {
			return "refused";
		}
		const keyId = bearerTokensToKeyId.get(bearerToken);
		if (keyId === undefined) {
			return "refused";
		}
		const keyRec = retainedKeys.get(keyId);
		if (keyRec === undefined || keyRec.proofMode !== "bearer" || keyRec.generation !== generation) {
			return "refused";
		}
		return executeRedemptionTransaction(keyRec, use, remoteNodeId);
	};

	const beginPskArrival = (
		uses: AdmissionUsePool,
		callbacks: AdmissionHandoffCallbacks,
		arrival: object,
	): BeginPskArrivalResult => {
		if (typeof uses !== "object" || uses === null || typeof uses.reserveAdmissionUse !== "function") {
			throw new TypeError("beginPskArrival requires an AdmissionUsePool with reserveAdmissionUse()");
		}
		const reservation = uses.reserveAdmissionUse();
		if (reservation.kind === "refused") {
			return Object.freeze({ kind: "refused", reason: reservation.reason });
		}
		const use = reservation.use;
		try {
			if (typeof callbacks !== "object" || callbacks === null || typeof callbacks.acceptAdmission !== "function") {
				throw new TypeError("beginPskArrival requires callbacks with acceptAdmission(handoff)");
			}
			if (typeof arrival !== "object" || arrival === null) {
				throw new TypeError("beginPskArrival requires a non-null arrival object");
			}
		} catch (setupError) {
			if (typeof use.finishAdmissionAcquisition === "function") {
				callVoidHook(() => use.finishAdmissionAcquisition!());
			}
			throw setupError;
		}

		let currentLookupRef: object | undefined;
		let proofOutcome: "none" | "redeemed" | "refused" = "none";
		let channelAccepted = false;
		let hostStepSettled = false;
		let carrierSettled = false;
		let finished = false;
		let resolveSettled!: () => void;
		const settled = new Promise<void>((resolve) => {
			resolveSettled = resolve;
		});

		const disposeHostChannel = (channel: { close?(): void; dispose?(): void }): void => {
			if (typeof channel.close === "function") {
				callVoidHook(() => channel.close!());
			} else if (typeof channel.dispose === "function") {
				callVoidHook(() => channel.dispose!());
			}
		};

		const revokeUse = (): void => {
			callVoidHook(() => use.control.requestAdmissionTermination());
		};

		const maybeFinishComposition = (): void => {
			if (finished) return;
			if (!carrierSettled || !hostStepSettled) return;
			finished = true;
			if (typeof use.finishAdmissionAcquisition === "function") {
				callVoidHook(() => use.finishAdmissionAcquisition!());
			}
			resolveSettled();
		};

		const attempt: NativePskProofAttempt = Object.freeze({
			kind: "reserved" as const,
			arrival,
			use,
			resolvePsk(pskIdentity: string): ResolvePskResult {
				const res = resolvePsk(pskIdentity, { arrival });
				if (res.kind === "resolved") {
					currentLookupRef = res.lookupRef;
				}
				return res;
			},
			completePskProof(proof: { readonly arrival: object; readonly lookupRef: object }): "redeemed" | "refused" {
				const res = completePskProof(
					{
						arrival,
						use,
						...(currentLookupRef === undefined ? {} : { lookupRef: currentLookupRef }),
					},
					proof,
				);
				proofOutcome = res;
				return res;
			},
			acceptPskChannel(channel: { close?(): void; dispose?(): void }): void {
				if (typeof channel !== "object" || channel === null) {
					throw new TypeError("acceptPskChannel requires a channel object");
				}
				// If carrierAcquisitionSettled already ran on a no-channel path, refuse and dispose the late channel.
				if (carrierSettled && !channelAccepted) {
					revokeUse();
					disposeHostChannel(channel);
					return;
				}
				if (channelAccepted) {
					disposeHostChannel(channel);
					return;
				}
				channelAccepted = true;
				// Record host custody and return normally first; run seal + acceptAdmission in a bounded continuation (D72, F8).
				queueMicrotask(() => {
					try {
						if (proofOutcome !== "redeemed" || typeof use.sealAdmissionHandoff !== "function") {
							revokeUse();
							disposeHostChannel(channel);
							return;
						}
						const sealed = use.sealAdmissionHandoff(channel);
						if (
							typeof sealed !== "object" ||
							sealed === null ||
							sealed.kind !== "sealed" ||
							typeof (sealed as { readonly handoff?: unknown }).handoff !== "object" ||
							(sealed as { readonly handoff?: unknown }).handoff === null
						) {
							revokeUse();
							disposeHostChannel(channel);
							return;
						}
						try {
							const acceptRet = callbacks.acceptAdmission(sealed.handoff);
							observePromises(acceptRet);
						} catch (acceptErr) {
							observePromises(acceptErr);
							revokeUse();
							disposeHostChannel(channel);
						}
					} catch (sealErr) {
						observePromises(sealErr);
						revokeUse();
						disposeHostChannel(channel);
					} finally {
						hostStepSettled = true;
						maybeFinishComposition();
					}
				});
			},
			carrierAcquisitionSettled(): void {
				if (carrierSettled) return;
				carrierSettled = true;
				if (!channelAccepted) {
					if (proofOutcome !== "none") {
						revokeUse();
					}
					hostStepSettled = true;
				}
				maybeFinishComposition();
			},
			settled,
		});

		return attempt;
	};

	const verifyRedeemed = (input: RedeemedAdmissionVerifyInput): RedeemedAdmissionVerifyResult => {
		if (typeof input !== "object" || input === null) {
			return Object.freeze({ ok: false, reasonCode: "SECURITY_EVIDENCE" });
		}
		const { redemptionId, lifecycle, remoteNodeId } = input;
		if (
			!isValidBoundedIdentifier(redemptionId) ||
			typeof lifecycle !== "object" ||
			lifecycle === null ||
			!isValidBoundedIdentifier(remoteNodeId)
		) {
			return Object.freeze({ ok: false, reasonCode: "SECURITY_EVIDENCE" });
		}
		const slot = slotsByLifecycle.get(lifecycle);
		if (
			slot === undefined ||
			slot.compacted ||
			slot.state !== "committed" ||
			slot.generation !== generation ||
			slot.redemptionId !== redemptionId ||
			slot.lifecycle !== lifecycle
		) {
			return Object.freeze({ ok: false, reasonCode: "SECURITY_EVIDENCE" });
		}
		const lease = activeLeases.get(leaseKey(slot.hub, slot.node));
		if (lease === undefined || lease.instanceBinding !== slot.instanceBinding) {
			return Object.freeze({ ok: false, reasonCode: "SECURITY_EVIDENCE" });
		}
		if (remoteNodeId !== slot.node) {
			return Object.freeze({ ok: false, reasonCode: "EXPECTED_NODE_MISMATCH" });
		}
		return Object.freeze({
			ok: true,
			issuer: slot.issuer,
			principal: slot.principal,
			instanceBinding: slot.instanceBinding,
		});
	};

	const redeemer: CredentialRedeemer = Object.freeze({
		resolvePsk,
		completePskProof,
		beginPskArrival,
		redeemBearer,
		verifyRedeemed,
		sweepLeases,
	});

	return Object.freeze({
		hub,
		generation,
		clock,
		redeemer,
		mintStandingCode,
		listStandingCodes,
		revokeStandingCode,
		issueAdmissionKey,
		resolvePsk,
		completePskProof,
		beginPskArrival,
		redeemBearer,
		verifyRedeemed,
		sweepLeases,
	});
}
