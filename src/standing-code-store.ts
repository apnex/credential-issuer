/**
 * Standing-code record validation and in-memory standing-code store (`CIss1`, `D54`, `D55`).
 */
import { readPlainJson } from "@apnex/shape-check";
import type { StandingCodeRecord, StandingCodeStore } from "./issuer-types.js";
import { isValidBoundedIdentifier, isValidIdentity, isValidIssuer } from "./sha256.js";

const HASH_PATTERN = /^[0-9a-f]{64}$/;

/** Validates one `StandingCodeRecord` through `readPlainJson` (`CIss1`, `D54`), returning a frozen record or `null`. */
export function readStandingCodeRecord(raw: unknown): StandingCodeRecord | null {
	const plain = readPlainJson(raw);
	if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
		return null;
	}
	const obj = plain.value as Record<string, unknown>;
	const keys = Object.keys(obj);
	if (keys.length !== 8) return null;
	for (const k of keys) {
		if (
			k !== "codeId" &&
			k !== "codeHash" &&
			k !== "identity" &&
			k !== "minterPrincipal" &&
			k !== "minterIssuer" &&
			k !== "createdAtMs" &&
			k !== "expiresAtMs" &&
			k !== "revokedAtMs"
		) {
			return null;
		}
	}
	const {
		codeId,
		codeHash,
		identity,
		minterPrincipal,
		minterIssuer,
		createdAtMs,
		expiresAtMs,
		revokedAtMs,
	} = obj;
	if (!isValidBoundedIdentifier(codeId)) return null;
	if (typeof codeHash !== "string" || !HASH_PATTERN.test(codeHash)) return null;
	if (!isValidIdentity(identity)) return null;
	if (!isValidBoundedIdentifier(minterPrincipal)) return null;
	if (!isValidIssuer(minterIssuer)) return null;
	if (typeof createdAtMs !== "number" || !Number.isFinite(createdAtMs)) return null;
	if (expiresAtMs !== null && (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs))) return null;
	if (revokedAtMs !== null && (typeof revokedAtMs !== "number" || !Number.isFinite(revokedAtMs))) return null;
	return Object.freeze({
		codeId,
		codeHash,
		identity,
		minterPrincipal,
		minterIssuer,
		createdAtMs,
		expiresAtMs,
		revokedAtMs,
	});
}

/** Validates an array of `StandingCodeRecord`s (checking uniqueness of `codeId` and `codeHash`), or returns `null`. */
export function readStandingCodeRecordList(raw: unknown): readonly StandingCodeRecord[] | null {
	if (!Array.isArray(raw)) return null;
	const seenIds = new Set<string>();
	const seenHashes = new Set<string>();
	const out: StandingCodeRecord[] = [];
	for (const item of raw) {
		const rec = readStandingCodeRecord(item);
		if (rec === null) return null;
		if (seenIds.has(rec.codeId) || seenHashes.has(rec.codeHash)) return null;
		seenIds.add(rec.codeId);
		seenHashes.add(rec.codeHash);
		out.push(rec);
	}
	return Object.freeze(out);
}

/** Creates an in-memory `StandingCodeStore` (`CIss1`). */
export function createMemoryStandingCodeStore(initialRecords: readonly StandingCodeRecord[] = []): StandingCodeStore {
	const initial = readStandingCodeRecordList(initialRecords);
	if (initial === null) {
		throw new TypeError("initialRecords must be an array of valid StandingCodeRecord objects with unique codeId and codeHash");
	}
	let current: readonly StandingCodeRecord[] = initial;
	return Object.freeze({
		load(): readonly StandingCodeRecord[] {
			return current;
		},
		save(records: readonly StandingCodeRecord[]): void {
			const validated = readStandingCodeRecordList(records);
			if (validated === null) {
				throw new TypeError("records must be an array of valid StandingCodeRecord objects with unique codeId and codeHash");
			}
			current = validated;
		},
	});
}
