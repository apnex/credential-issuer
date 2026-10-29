/**
 * Client credential presentation (`createCredentialPresenterTarget`, `A3`) and refusal observation
 * (`observeAdjacencyRefusal`, `A4`) for `CIss5` (`fresh-key-per-dial`).
 */
import { observePromises, readPlainJson, toCanonicalJson, type JsonInput } from "@apnex/shape-check";
import { defaultClock, type ClockPort } from "./clock-adapter.js";
import type {
	AdjacencyRefusalObserver,
	AdjacencyRefusalObserverOptions,
	AdmissionKeyProofMode,
	ClientPrimaryProof,
	CredentialAttempt,
	CredentialCarrierReservation,
	CredentialPresenterTarget,
	CredentialPresenterTargetOptions,
	IssueAdmissionKeyRefusalCode,
	IssueAdmissionKeyRequest,
	PrepareCredentialResult,
} from "./issuer-types.js";
import {
	bytesToHex,
	hexToBytes,
	isValidBoundedIdentifier,
	isValidIssuer,
	isValidPrintableAsciiPskIdentity,
	parseNodeId,
	readExactUint8Array,
} from "./sha256.js";

const EXPLICIT_REFUSAL_CODES = new Set<IssueAdmissionKeyRefusalCode>([
	"proof-refused",
	"policy-refused",
	"node-identity-conflict",
	"wrong-hub",
	"invalid-node",
	"invalid-proof-mode",
	"incompatible-psk-identity",
]);

/** Awaits a native `Promise` via `Promise.prototype.then`, or settles synchronously (`D54`, `D55`). */
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

/** Reads and deeply snapshots a `ClientPrimaryProof` via own enumerable data descriptors and `readPlainJson` (`CIss5`, `F4`, `F6`). */
function snapshotPrimaryProof(raw: unknown): ClientPrimaryProof {
	const captured: unknown[] = [raw];
	const failProof = (message: string): never => {
		for (const item of captured) observePromises(item);
		throw new TypeError(message);
	};
	try {
		if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
			return failProof("getProof() must return a plain object { kind: \"sign-in\", token } or { kind: \"standing-code\", code }");
		}
		const proto = Object.getPrototypeOf(raw);
		if (proto !== Object.prototype && proto !== null) {
			return failProof("getProof() must return a plain object");
		}
		if (Object.getOwnPropertySymbols(raw).length > 0) {
			return failProof("getProof() result must not carry symbol properties");
		}
		const names = Object.getOwnPropertyNames(raw);
		const props = new Map<string, unknown>();
		for (const name of names) {
			const desc = Object.getOwnPropertyDescriptor(raw, name);
			if (desc !== undefined && Object.hasOwn(desc, "value")) {
				captured.push(desc.value);
			}
			if (desc === undefined || !desc.enumerable || !Object.hasOwn(desc, "value")) {
				return failProof("getProof() properties must be own enumerable data descriptors");
			}
			props.set(name, desc.value);
		}
		if (names.length !== 2) {
			return failProof("getProof() result must have exactly two own properties");
		}
		const kind = props.get("kind");
		if (kind === "sign-in") {
			if (!props.has("token")) {
				return failProof("sign-in proof must have an own enumerable data property token");
			}
			const tokenVal = props.get("token");
			if (tokenVal === undefined || tokenVal === null) {
				return failProof("sign-in proof token must not be null or undefined");
			}
			const tokenPlain = readPlainJson(tokenVal);
			if (!tokenPlain.ok || tokenPlain.value === null) {
				return failProof("sign-in proof token must be a non-null plain JSON value");
			}
			return Object.freeze({ kind: "sign-in", token: tokenPlain.value });
		}
		if (kind === "standing-code") {
			const codeVal = props.get("code");
			if (typeof codeVal !== "string" || codeVal.length === 0) {
				return failProof("standing-code proof must have a non-empty string code");
			}
			return Object.freeze({ kind: "standing-code", code: codeVal });
		}
		return failProof("getProof() kind must be \"sign-in\" or \"standing-code\"");
	} catch (error) {
		captured.push(error);
		for (const item of captured) observePromises(item);
		if (error instanceof TypeError) {
			throw error;
		}
		throw new TypeError("getProof() threw or failed descriptor inspection", { cause: error });
	}
}

function samePrimaryProof(a: ClientPrimaryProof, b: ClientPrimaryProof): boolean {
	if (a.kind !== b.kind) return false;
	if (a.kind === "sign-in" && b.kind === "sign-in") {
		return toCanonicalJson(a.token as JsonInput) === toCanonicalJson(b.token as JsonInput);
	}
	if (a.kind === "standing-code" && b.kind === "standing-code") {
		return a.code === b.code;
	}
	return false;
}

/**
 * Reads the result of `issueKey` across the plain-JSON / in-process `Uint8Array(32)` boundary (`o:F1`, `F5`, `F7`, `D54`, `D55`).
 */
function readIssueKeyResult(
	raw: unknown,
	expectedHub: string,
	expectedNode: string,
	clock: ClockPort,
):
	| {
			readonly kind: "ok";
			readonly key: {
				readonly redemptionId: string;
				readonly pskIdentity: string;
				readonly secret: Uint8Array;
				readonly secretHex: string;
				readonly bearerToken: string;
				readonly proofMode: AdmissionKeyProofMode;
				readonly issuer: string;
				readonly principal: string;
				readonly hub: string;
				readonly node: string;
				readonly instanceBinding: string;
				readonly continuationSecret: string;
				readonly validBeforeMonotonicMs: number;
			};
	  }
	| { readonly kind: "refused"; readonly code: IssueAdmissionKeyRefusalCode }
	| { readonly kind: "unavailable"; readonly reason: string } {
	const captured: unknown[] = [raw];
	const failUnavailable = (reason: string): { readonly kind: "unavailable"; readonly reason: string } => {
		for (const item of captured) observePromises(item);
		return { kind: "unavailable", reason };
	};

	try {
		if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
			return failUnavailable("malformed-issue-key-response");
		}
		const proto = Object.getPrototypeOf(raw);
		if (proto !== Object.prototype && proto !== null) {
			return failUnavailable("malformed-issue-key-response");
		}
		if (Object.getOwnPropertySymbols(raw).length > 0) {
			return failUnavailable("malformed-issue-key-response");
		}

		// Extract optional in-process Uint8Array `secret` via own data descriptor before passing plain JSON fields to readPlainJson.
		let extractedSecretBytes: Uint8Array | undefined;
		let hadSecretProp = false;
		const plainCandidate: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(raw)) {
			const desc = Object.getOwnPropertyDescriptor(raw, key);
			if (desc !== undefined && Object.hasOwn(desc, "value")) {
				captured.push(desc.value);
			}
			if (desc === undefined || !desc.enumerable || !Object.hasOwn(desc, "value")) {
				return failUnavailable("malformed-issue-key-response");
			}
			if (key === "secret") {
				hadSecretProp = true;
				const copiedSecret = readExactUint8Array(desc.value, 32);
				if (copiedSecret === null) {
					return failUnavailable("malformed-psk-secret");
				}
				extractedSecretBytes = copiedSecret;
			} else {
				Object.defineProperty(plainCandidate, key, {
					value: desc.value,
					enumerable: true,
					writable: true,
					configurable: true,
				});
			}
		}

		const plain = readPlainJson(plainCandidate);
		if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
			return failUnavailable("malformed-issue-key-response");
		}
		const obj = plain.value as Record<string, unknown>;
		if (obj.ok === false) {
			if (hadSecretProp || Object.keys(obj).length !== 2 || typeof obj.code !== "string") {
				return failUnavailable("malformed-refusal");
			}
			if (EXPLICIT_REFUSAL_CODES.has(obj.code as IssueAdmissionKeyRefusalCode)) {
				return { kind: "refused", code: obj.code as IssueAdmissionKeyRefusalCode };
			}
			return { kind: "unavailable", reason: obj.code };
		}
		if (obj.ok !== true) {
			return failUnavailable("malformed-issue-key-response");
		}

		const {
			redemptionId,
			pskIdentity,
			secretHex,
			bearerToken,
			proofMode,
			issuer,
			principal,
			hub,
			node,
			instanceBinding,
			continuationSecret,
			validBeforeMonotonicMs,
		} = obj;

		if (
			!isValidBoundedIdentifier(redemptionId) ||
			pskIdentity !== redemptionId ||
			!isValidPrintableAsciiPskIdentity(pskIdentity, 127) ||
			typeof bearerToken !== "string" ||
			bearerToken.length === 0 ||
			(proofMode !== "native-tls13-external-psk-v1" && proofMode !== "bearer") ||
			!isValidIssuer(issuer) ||
			!isValidBoundedIdentifier(principal) ||
			hub !== expectedHub ||
			node !== expectedNode ||
			!isValidBoundedIdentifier(instanceBinding) ||
			typeof continuationSecret !== "string" ||
			continuationSecret.length === 0 ||
			typeof validBeforeMonotonicMs !== "number" ||
			!Number.isFinite(validBeforeMonotonicMs)
		) {
			return failUnavailable("malformed-issue-key-fields");
		}

		let finalSecret: Uint8Array;
		let finalSecretHex: string;
		if ("secretHex" in obj) {
			if (typeof secretHex !== "string") {
				return failUnavailable("malformed-psk-secret");
			}
			const decoded = hexToBytes(secretHex, 32);
			if (decoded === null) {
				return failUnavailable("malformed-psk-secret");
			}
			if (extractedSecretBytes !== undefined && bytesToHex(extractedSecretBytes) !== secretHex) {
				return failUnavailable("mismatched-psk-secret");
			}
			finalSecret = decoded;
			finalSecretHex = secretHex;
		} else if (extractedSecretBytes !== undefined) {
			finalSecret = extractedSecretBytes;
			finalSecretHex = bytesToHex(extractedSecretBytes);
		} else {
			return failUnavailable("missing-psk-secret");
		}

		// Sample clock AFTER all response reflection and validation completes (F7).
		if (!(clock.now() < validBeforeMonotonicMs)) {
			return failUnavailable("expired-key");
		}

		return {
			kind: "ok",
			key: {
				redemptionId,
				pskIdentity,
				secret: finalSecret,
				secretHex: finalSecretHex,
				bearerToken,
				proofMode,
				issuer,
				principal,
				hub,
				node,
				instanceBinding,
				continuationSecret,
				validBeforeMonotonicMs,
			},
		};
	} catch (error) {
		captured.push(error);
		return failUnavailable("exception-reading-issue-key");
	}
}

/** Creates a client credential-presenter target (`CIss5`, `A3`). */
export function createCredentialPresenterTarget(
	options: CredentialPresenterTargetOptions,
): CredentialPresenterTarget {
	if (typeof options !== "object" || options === null) {
		throw new TypeError("createCredentialPresenterTarget requires an options object");
	}
	const { hub, node, getProof, issueKey, connectWithKey } = options;
	if (!isValidBoundedIdentifier(hub)) {
		throw new TypeError("options.hub must be a valid bounded identifier");
	}
	if (parseNodeId(node) === null) {
		throw new TypeError("options.node must match <identity>.<16 lowercase hex>");
	}
	const proofMode: AdmissionKeyProofMode = options.proofMode ?? "native-tls13-external-psk-v1";
	if (proofMode !== "native-tls13-external-psk-v1" && proofMode !== "bearer") {
		throw new TypeError("options.proofMode must be \"native-tls13-external-psk-v1\" or \"bearer\"");
	}
	if (typeof getProof !== "function") {
		throw new TypeError("options.getProof must be a function");
	}
	if (typeof issueKey !== "function") {
		throw new TypeError("options.issueKey must be a function");
	}
	if (typeof connectWithKey !== "function") {
		throw new TypeError("options.connectWithKey must be a function");
	}
	const clock: ClockPort = options.clock ?? defaultClock;
	if (typeof clock !== "object" || clock === null || typeof clock.now !== "function" || typeof clock.schedule !== "function") {
		throw new TypeError("options.clock must be a ClockPort");
	}

	let continuationSecret: string | null = null;

	return Object.freeze({
		hub,
		node,
		getContinuationSecret(): string | null {
			return continuationSecret;
		},
		setContinuationSecret(secret: string | null): void {
			if (secret !== null && (typeof secret !== "string" || secret.length === 0)) {
				throw new TypeError("continuationSecret must be a non-empty string or null");
			}
			continuationSecret = secret;
		},
		createCredentialAttempt(
			request: { readonly hub?: string; readonly node?: string } | undefined,
			permit: CredentialCarrierReservation,
		): CredentialAttempt {
			// Synchronous no-I/O constructor: validate permit, request, and snapshot primary proof BEFORE taking permit custody (A3).
			if (typeof permit !== "object" || permit === null || typeof permit.releaseUnused !== "function") {
				throw new TypeError("createCredentialAttempt requires a permit with releaseUnused()");
			}
			if (request !== undefined) {
				if (typeof request !== "object" || request === null) {
					throw new TypeError("request must be an object when supplied");
				}
				if (request.hub !== undefined && request.hub !== hub) {
					throw new TypeError("request.hub does not match presenter hub");
				}
				if (request.node !== undefined && request.node !== node) {
					throw new TypeError("request.node does not match presenter node");
				}
			}
			let rawProof: unknown;
			try {
				rawProof = getProof();
			} catch (proofError) {
				observePromises(proofError);
				throw proofError;
			}
			const capturedProof = snapshotPrimaryProof(rawProof);
			const capturedContinuation = continuationSecret;

			let prepareStarted = false;
			let connectStarted = false;
			let disposed = false;
			let channelTransferred = false;
			let permitReleased = false;
			let createdSocket: { readonly closed?: Promise<void>; close?(): void } | undefined;
			let inFlightPrepare: Promise<void> | undefined;
			let inFlightConnect: Promise<void> | undefined;
			let disposePromise: Promise<void> | undefined;
			let heldKey: {
				readonly redemptionId: string;
				readonly pskIdentity: string;
				readonly secret: Uint8Array;
				readonly secretHex: string;
				readonly bearerToken: string;
				readonly proofMode: AdmissionKeyProofMode;
				readonly hub: string;
				readonly node: string;
				readonly instanceBinding: string;
				readonly validBeforeMonotonicMs: number;
			} | null = null;

			const zeroOutKey = (): void => {
				if (heldKey !== null) {
					heldKey.secret.fill(0);
					heldKey = null;
				}
			};

			const releasePermitOnce = (): void => {
				if (permitReleased) return;
				permitReleased = true;
				try {
					const ret = permit.releaseUnused();
					observePromises(ret);
				} catch (err) {
					observePromises(err);
				}
			};

			const prepareCredential = (signal?: AbortSignal): Promise<PrepareCredentialResult> => {
				if (prepareStarted || disposed || signal?.aborted === true) {
					return Promise.resolve(Object.freeze({ kind: "issuer-unavailable", reason: "disposed-or-aborted" }));
				}
				prepareStarted = true;
				let resolveInFlightPrepare!: () => void;
				// Establish inFlightPrepare BEFORE invoking issueKey so reentrant attempt.dispose() inside issueKey waits (F2).
				inFlightPrepare = new Promise<void>((resolve) => {
					resolveInFlightPrepare = resolve;
				});

				const runPrepare = async (): Promise<PrepareCredentialResult> => {
					try {
						const issueReq: IssueAdmissionKeyRequest = capturedProof.kind === "sign-in"
							? Object.freeze({
									grantType: "urn:ietf:params:oauth:grant-type:token-exchange" as const,
									subjectToken: capturedProof.token,
									hub,
									node,
									proofMode,
									...(capturedContinuation !== null ? { continuationSecret: capturedContinuation } : {}),
							  })
							: Object.freeze({
									grantType: "client_credentials" as const,
									clientSecret: capturedProof.code,
									hub,
									node,
									proofMode,
									...(capturedContinuation !== null ? { continuationSecret: capturedContinuation } : {}),
							  });

						let raw: unknown;
						try {
							raw = issueKey(issueReq, signal);
						} catch (error) {
							observePromises(error);
							return Object.freeze({ kind: "issuer-unavailable", reason: "issue-key-threw" });
						}
						const settled = await settleNativePromiseOrValue(raw);
						if (!settled.ok) {
							return Object.freeze({ kind: "issuer-unavailable", reason: "issue-key-rejected" });
						}
						if (disposed || signal?.aborted === true) {
							observePromises(settled.value);
							return Object.freeze({ kind: "issuer-unavailable", reason: "disposed-or-aborted" });
						}

						const parsed = readIssueKeyResult(settled.value, hub, node, clock);
						if (parsed.kind === "unavailable") {
							return Object.freeze({ kind: "issuer-unavailable", reason: parsed.reason });
						}
						if (parsed.kind === "refused") {
							if (parsed.code === "node-identity-conflict" && continuationSecret === capturedContinuation) {
								continuationSecret = null;
							}
							// Only classify as issuer-refused if the captured proof is still the current primary proof (A3).
							let stillCurrentProof = false;
							try {
								const currentProof = snapshotPrimaryProof(getProof());
								stillCurrentProof = samePrimaryProof(capturedProof, currentProof);
							} catch (err) {
								observePromises(err);
								stillCurrentProof = false;
							}
							if (!stillCurrentProof) {
								return Object.freeze({ kind: "issuer-unavailable", reason: "proof-superseded" });
							}
							return Object.freeze({ kind: "issuer-refused", code: parsed.code });
						}

						// Valid fresh key obtained: store continuationSecret for (hub, node) renewals.
						continuationSecret = parsed.key.continuationSecret;
						heldKey = parsed.key;

						const connection = Object.freeze({
							markChannelTransferred(): void {
								channelTransferred = true;
							},
							async connect(connectSignal?: AbortSignal): Promise<{ readonly channel?: object }> {
								if (connectStarted) {
									throw new Error("connection.connect(signal) may be called at most once per attempt");
								}
								if (disposed || connectSignal?.aborted === true) {
									zeroOutKey();
									throw new Error("credential attempt is already disposed or aborted");
								}
								connectStarted = true;
								let resolveInFlightConnect!: () => void;
								inFlightConnect = new Promise<void>((resolve) => {
									resolveInFlightConnect = resolve;
								});
								const keyToUse = heldKey!;
								heldKey = null;
								const keyForConnect = Object.freeze({
									redemptionId: keyToUse.redemptionId,
									pskIdentity: keyToUse.pskIdentity,
									secret: new Uint8Array(keyToUse.secret),
									secretHex: keyToUse.secretHex,
									bearerToken: keyToUse.bearerToken,
									proofMode: keyToUse.proofMode,
									hub: keyToUse.hub,
									node: keyToUse.node,
									instanceBinding: keyToUse.instanceBinding,
									validBeforeMonotonicMs: keyToUse.validBeforeMonotonicMs,
								});
								keyToUse.secret.fill(0);

								try {
									const rawConnect = await connectWithKey(keyForConnect, connectSignal);
									if (typeof rawConnect === "object" && rawConnect !== null) {
										if (typeof rawConnect.socket === "object" && rawConnect.socket !== null) {
											createdSocket = rawConnect.socket;
										}
										if (rawConnect.transferred === true) {
											channelTransferred = true;
										}
										return Object.freeze(
											rawConnect.channel !== undefined ? { channel: rawConnect.channel } : {},
										);
									}
									return Object.freeze({});
								} catch (err) {
									observePromises(err);
									throw err;
								} finally {
									resolveInFlightConnect();
								}
							},
						});

						return Object.freeze({
							kind: "prepared",
							keyMeta: Object.freeze({
								redemptionId: parsed.key.redemptionId,
								instanceBinding: parsed.key.instanceBinding,
								validBeforeMonotonicMs: parsed.key.validBeforeMonotonicMs,
							}),
							connection,
						});
					} finally {
						resolveInFlightPrepare();
					}
				};

				return runPrepare();
			};

			const dispose = (): Promise<void> => {
				if (disposePromise !== undefined) return disposePromise;
				disposed = true;
				zeroOutKey();

				disposePromise = (async (): Promise<void> => {
					// Wait for all in-flight source/proof work and any potential socket creator to settle first.
					if (inFlightPrepare !== undefined) {
						await inFlightPrepare;
					}
					if (inFlightConnect !== undefined) {
						await inFlightConnect;
					}
					zeroOutKey();

					// Case 3: channel custody transferred to the node -> settle only acquisition-owned work,
					// never close the transferred channel, and never refund or discharge permit.
					if (channelTransferred) {
						return;
					}

					// Case 2: untransferred socket was created -> capture createdSocket.closed once, require that
					// captured value to be a native Promise, and await that exact value before releasing permit (A3, F3, F7).
					if (createdSocket !== undefined) {
						try {
							const closeRet = createdSocket.close?.();
							observePromises(closeRet);
						} catch (closeErr) {
							observePromises(closeErr);
						}
						let closedReceipt: unknown;
						let hasNativeClosedReceipt = false;
						try {
							closedReceipt = createdSocket.closed;
							hasNativeClosedReceipt = closedReceipt instanceof Promise;
						} catch (err) {
							observePromises(err);
							observePromises(closedReceipt);
						}
						if (!hasNativeClosedReceipt) {
							observePromises(closedReceipt);
							return;
						}
						const closedSettled = await settleNativePromiseOrValue(closedReceipt);
						if (!closedSettled.ok) {
							return;
						}
						releasePermitOnce();
						return;
					}

					// Case 1: no socket was created -> release permit after all in-flight work settled.
					releasePermitOnce();
				})();

				return disposePromise;
			};

			return Object.freeze({
				prepareCredential,
				dispose,
			});
		},
	});
}

/** Subscribes to adjacency credential events and observes `issuer-refused` transitions (`CIss5`, `A4`). */
export function observeAdjacencyRefusal(options: AdjacencyRefusalObserverOptions): AdjacencyRefusalObserver {
	if (typeof options !== "object" || options === null) {
		throw new TypeError("observeAdjacencyRefusal requires an options object");
	}
	const { adjacencyId, events, readAdjacencies, notifyCredentialChange, installProof, onAdmissionRefused } = options;
	if (!isValidBoundedIdentifier(adjacencyId)) {
		throw new TypeError("options.adjacencyId must be a valid bounded identifier");
	}
	if (typeof events !== "function") {
		throw new TypeError("options.events must be a function");
	}
	if (typeof readAdjacencies !== "function") {
		throw new TypeError("options.readAdjacencies must be a function");
	}
	if (typeof notifyCredentialChange !== "function") {
		throw new TypeError("options.notifyCredentialChange must be a function");
	}
	if (installProof !== undefined && typeof installProof !== "function") {
		throw new TypeError("options.installProof must be a function when supplied");
	}
	if (onAdmissionRefused !== undefined && typeof onAdmissionRefused !== "function") {
		throw new TypeError("options.onAdmissionRefused must be a function when supplied");
	}

	let stopped = false;
	let minRequiredGeneration = 0;
	let lastNotifiedRefusedGeneration = -1;
	let currentStatus: {
		readonly admissionRefused: boolean;
		readonly proxyCode: "admission-refused" | null;
		readonly phase: string;
		readonly generation: number;
		readonly code?: string;
	} = Object.freeze({
		admissionRefused: false,
		proxyCode: null,
		phase: "idle",
		generation: 0,
	});

	const readCurrentSnapshot = (): typeof currentStatus => {
		let raw: unknown;
		try {
			raw = readAdjacencies();
		} catch (error) {
			observePromises(error);
			return currentStatus;
		}
		const plain = readPlainJson(raw);
		if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
			return currentStatus;
		}
		const items = (plain.value as { readonly items?: unknown }).items;
		if (!Array.isArray(items)) return currentStatus;
		const match = items.find(
			(item): item is Record<string, unknown> =>
				typeof item === "object" &&
				item !== null &&
				!Array.isArray(item) &&
				(item as { readonly adjacencyId?: unknown }).adjacencyId === adjacencyId,
		);
		if (match === undefined) return currentStatus;

		const adopted = match.adopted === true;
		const cred = match.credential;
		if (typeof cred !== "object" || cred === null || Array.isArray(cred)) {
			return currentStatus;
		}
		const credObj = cred as Record<string, unknown>;
		const phase = typeof credObj.phase === "string" ? credObj.phase : "idle";
		const generation = typeof credObj.generation === "number" && Number.isInteger(credObj.generation) && credObj.generation >= 0
			? credObj.generation
			: 0;
		const code = typeof credObj.code === "string" ? credObj.code : undefined;

		// Never restore an older generation below minRequiredGeneration (unless terminal "inactive").
		if (phase !== "inactive" && generation < minRequiredGeneration) {
			return currentStatus;
		}
		minRequiredGeneration = Math.max(minRequiredGeneration, generation);

		// Map ONLY current credential.phase === "issuer-refused" (when not adopted) to "admission-refused" (A4).
		const isRefused = !adopted && phase === "issuer-refused";
		currentStatus = Object.freeze({
			admissionRefused: isRefused,
			proxyCode: isRefused ? ("admission-refused" as const) : null,
			phase,
			generation,
			...(code !== undefined ? { code } : {}),
		});

		if (isRefused && generation > lastNotifiedRefusedGeneration && onAdmissionRefused !== undefined) {
			lastNotifiedRefusedGeneration = generation;
			try {
				const ret = onAdmissionRefused(
					Object.freeze({
						adjacencyId,
						generation,
						...(code !== undefined ? { code } : {}),
					}),
				);
				observePromises(ret);
			} catch (err) {
				observePromises(err);
			}
		}

		return currentStatus;
	};

	// Subscribe to events() BEFORE initial read of readAdjacencies() (A4).
	let unsubscribe: (() => void) | undefined;
	const eventSource = events();
	if (typeof eventSource === "object" && eventSource !== null) {
		if ("subscribe" in eventSource && typeof eventSource.subscribe === "function") {
			const sub = eventSource.subscribe((ev) => {
				if (stopped) return;
				if (
					ev?.type === "gap" ||
					ev?.type === "adjacency.credential-changed" ||
					ev?.adjacencyId === undefined ||
					ev?.adjacencyId === adjacencyId
				) {
					readCurrentSnapshot();
				}
			});
			unsubscribe = () => sub?.unsubscribe?.();
		} else if (Symbol.asyncIterator in eventSource) {
			const iter = (eventSource as AsyncIterable<{ readonly type: string; readonly adjacencyId?: string }>)[Symbol.asyncIterator]();
			void (async () => {
				try {
					while (!stopped) {
						const next = await iter.next();
						if (next.done || stopped) break;
						const ev = next.value;
						if (
							ev?.type === "gap" ||
							ev?.type === "adjacency.credential-changed" ||
							ev?.adjacencyId === undefined ||
							ev?.adjacencyId === adjacencyId
						) {
							readCurrentSnapshot();
						}
					}
				} catch (err) {
					observePromises(err);
				}
			})();
			unsubscribe = () => {
				void iter.return?.();
			};
		}
	}

	// Initial read after subscription is active.
	readCurrentSnapshot();

	return Object.freeze({
		getStatus() {
			return currentStatus;
		},
		refresh() {
			return readCurrentSnapshot();
		},
		async updateProofAndRearm(newProof: unknown) {
			// Install new primary proof BEFORE calling notifyCredentialChange(adjacencyId) (A4).
			if (installProof !== undefined) {
				installProof(newProof);
			}
			let rawReceipt: unknown;
			try {
				rawReceipt = notifyCredentialChange(adjacencyId);
			} catch (error) {
				observePromises(error);
				throw error;
			}
			const settled = await settleNativePromiseOrValue(rawReceipt);
			if (!settled.ok) {
				throw new Error("notifyCredentialChange rejected");
			}
			const plain = readPlainJson(settled.value);
			if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
				throw new TypeError("notifyCredentialChange must return { kind: \"committed\", generation } or { kind: \"inactive\" } as plain data");
			}
			const obj = plain.value as Record<string, unknown>;
			if (obj.kind === "inactive" && Object.keys(obj).length === 1) {
				currentStatus = Object.freeze({
					admissionRefused: false,
					proxyCode: null,
					phase: "inactive",
					generation: minRequiredGeneration,
				});
				return Object.freeze({
					kind: "inactive" as const,
					generation: minRequiredGeneration,
					status: currentStatus,
				});
			}
			if (
				obj.kind === "committed" &&
				Object.keys(obj).length === 2 &&
				typeof obj.generation === "number" &&
				Number.isInteger(obj.generation) &&
				obj.generation >= 0
			) {
				const receiptGen = obj.generation;
				minRequiredGeneration = Math.max(minRequiredGeneration, receiptGen);
				// Clear any stale refusal from < receiptGen before reading the updated snapshot.
				if (currentStatus.generation < receiptGen) {
					currentStatus = Object.freeze({
						admissionRefused: false,
						proxyCode: null,
						phase: "preparing",
						generation: receiptGen,
					});
				}
				const status = readCurrentSnapshot();
				return Object.freeze({
					kind: "committed" as const,
					generation: Math.max(receiptGen, status.generation),
					status,
				});
			}
			throw new TypeError("notifyCredentialChange returned an invalid receipt shape");
		},
		stop(): void {
			if (stopped) return;
			stopped = true;
			unsubscribe?.();
		},
	});
}
