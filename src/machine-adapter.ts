/**
 * Machine file adapter for durable standing-code storage (`@apnex/credential-issuer/machine`, `CIss1`).
 *
 * Refuses symbolic links or directories at `filePath` or `${filePath}.tmp` as `"code-store-unwritable"`,
 * refuses non-regular files (such as FIFOs/named pipes, sockets or devices) before opening `filePath` as
 * `"code-store-corrupt"`, validates the leading `{"store":"credential-issuer-codes","version":1}` header and
 * record lines through `readPlainJson`, and commits each `save(records)` atomically via `${filePath}.tmp`
 * (`O_CREAT | O_EXCL | O_WRONLY`, mode `0600`) + `fdatasyncSync` + `closeSync` + `renameSync` + parent-directory
 * `fsyncSync`, tagging any post-rename error with `afterRename: true` (`o:F6`).
 */
import fs from "node:fs";
import path from "node:path";
import { readPlainJson, toCanonicalJson } from "@apnex/shape-check";
import type { StandingCodeRecord, StandingCodeStore } from "./issuer-types.js";
import { readStandingCodeRecord, readStandingCodeRecordList } from "./standing-code-store.js";

/** Optional filesystem overrides for testing fault injection (`o:F6`, `CIss1`). */
export interface FileStoreFs {
	lstatSync: typeof fs.lstatSync;
	readFileSync: typeof fs.readFileSync;
	openSync: typeof fs.openSync;
	writeFileSync: typeof fs.writeFileSync;
	fdatasyncSync: typeof fs.fdatasyncSync;
	fsyncSync: typeof fs.fsyncSync;
	closeSync: typeof fs.closeSync;
	renameSync: typeof fs.renameSync;
	unlinkSync: typeof fs.unlinkSync;
}

const HEADER_JSON = "{\"store\":\"credential-issuer-codes\",\"version\":1}";

function codedError(
	code: "code-store-unwritable" | "code-store-corrupt",
	message: string,
	afterRename = false,
	cause?: unknown,
): Error & { code: string; afterRename: boolean } {
	const err = new Error(message, cause !== undefined ? { cause } : undefined) as Error & {
		code: string;
		afterRename: boolean;
	};
	err.code = code;
	err.afterRename = afterRename;
	return err;
}

function isValidHeader(line: string): boolean {
	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch {
		return false;
	}
	const plain = readPlainJson(parsed);
	if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
		return false;
	}
	const obj = plain.value as Record<string, unknown>;
	const keys = Object.keys(obj);
	return keys.length === 2 && obj.store === "credential-issuer-codes" && obj.version === 1;
}

/** Creates a durable file-backed `StandingCodeStore` at `filePath` (`CIss1`). */
export function createFileStandingCodeStore(
	filePath: string,
	fsOverrides?: Partial<FileStoreFs>,
): StandingCodeStore {
	if (typeof filePath !== "string" || filePath.length === 0 || filePath.includes("\u0000")) {
		throw new TypeError("filePath must be a non-empty string without NUL bytes");
	}
	const targetPath = path.resolve(filePath);
	const tmpPath = `${targetPath}.tmp`;
	const parentDir = path.dirname(targetPath);
	const ops: FileStoreFs = {
		lstatSync: fsOverrides?.lstatSync ?? fs.lstatSync,
		readFileSync: fsOverrides?.readFileSync ?? fs.readFileSync,
		openSync: fsOverrides?.openSync ?? fs.openSync,
		writeFileSync: fsOverrides?.writeFileSync ?? fs.writeFileSync,
		fdatasyncSync: fsOverrides?.fdatasyncSync ?? fs.fdatasyncSync,
		fsyncSync: fsOverrides?.fsyncSync ?? fs.fsyncSync,
		closeSync: fsOverrides?.closeSync ?? fs.closeSync,
		renameSync: fsOverrides?.renameSync ?? fs.renameSync,
		unlinkSync: fsOverrides?.unlinkSync ?? fs.unlinkSync,
	};

	const checkPathNotSymlinkOrDir = (p: string): fs.Stats | null => {
		try {
			const stat = ops.lstatSync(p);
			if (stat.isSymbolicLink() || stat.isDirectory()) {
				throw codedError("code-store-unwritable", `${p} must not be a symbolic link or directory`);
			}
			return stat;
		} catch (err) {
			if ((err as { code?: string })?.code === "code-store-unwritable") throw err;
			if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw codedError("code-store-unwritable", `cannot inspect ${p}`, false, err);
		}
	};

	return Object.freeze({
		load(): readonly StandingCodeRecord[] {
			const stat = checkPathNotSymlinkOrDir(targetPath);
			checkPathNotSymlinkOrDir(tmpPath);
			if (stat === null) {
				return Object.freeze([]);
			}
			if (!stat.isFile()) {
				throw codedError("code-store-corrupt", `${targetPath} is not a regular file`);
			}
			let text: string;
			try {
				text = ops.readFileSync(targetPath, "utf8");
			} catch (err) {
				throw codedError("code-store-unwritable", `cannot read ${targetPath}`, false, err);
			}
			const lines = text.split("\n").filter((l) => l.length > 0);
			if (lines.length === 0 || !isValidHeader(lines[0]!)) {
				throw codedError("code-store-corrupt", `${targetPath} has a missing or invalid header`);
			}
			const seenIds = new Set<string>();
			const seenHashes = new Set<string>();
			const records: StandingCodeRecord[] = [];
			for (let i = 1; i < lines.length; i++) {
				let parsed: unknown;
				try {
					parsed = JSON.parse(lines[i]!);
				} catch (err) {
					throw codedError("code-store-corrupt", `${targetPath} line ${i + 1} is not valid JSON`, false, err);
				}
				const rec = readStandingCodeRecord(parsed);
				if (rec === null || seenIds.has(rec.codeId) || seenHashes.has(rec.codeHash)) {
					throw codedError("code-store-corrupt", `${targetPath} line ${i + 1} is not a valid unique StandingCodeRecord`);
				}
				seenIds.add(rec.codeId);
				seenHashes.add(rec.codeHash);
				records.push(rec);
			}
			return Object.freeze(records);
		},

		save(records: readonly StandingCodeRecord[]): void {
			const validated = readStandingCodeRecordList(records);
			if (validated === null) {
				throw codedError("code-store-corrupt", "records passed to save are invalid");
			}
			const targetStat = checkPathNotSymlinkOrDir(targetPath);
			if (targetStat !== null && !targetStat.isFile()) {
				throw codedError("code-store-unwritable", `${targetPath} is not a regular file`);
			}
			const tmpStat = checkPathNotSymlinkOrDir(tmpPath);
			if (tmpStat !== null) {
				if (!tmpStat.isFile()) {
					throw codedError("code-store-unwritable", `${tmpPath} is not a regular file`);
				}
				try {
					ops.unlinkSync(tmpPath);
				} catch (err) {
					throw codedError("code-store-unwritable", `cannot remove stale ${tmpPath}`, false, err);
				}
			}
			const body = [HEADER_JSON, ...validated.map((r) => toCanonicalJson({ ...r }))].join("\n") + "\n";
			let fd: number | undefined;
			let renamed = false;
			try {
				fd = ops.openSync(tmpPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
				ops.writeFileSync(fd, body, "utf8");
				ops.fdatasyncSync(fd);
				ops.closeSync(fd);
				fd = undefined;
				ops.renameSync(tmpPath, targetPath);
				renamed = true;
				const dirFd = ops.openSync(parentDir, fs.constants.O_RDONLY);
				try {
					ops.fsyncSync(dirFd);
				} finally {
					ops.closeSync(dirFd);
				}
			} catch (err) {
				if (fd !== undefined) {
					try {
						ops.closeSync(fd);
					} catch {
						// ignore close error on unwind
					}
				}
				if (!renamed) {
					try {
						ops.unlinkSync(tmpPath);
					} catch {
						// ignore unlink error on unwind
					}
				}
				throw codedError("code-store-unwritable", `failed to save ${targetPath}`, renamed, err);
			}
		},
	});
}
