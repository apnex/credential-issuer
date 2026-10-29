/**
 * Public types of `@apnex/credential-issuer` and `@apnex/credential-issuer/machine` (`CIss1` to `CIss5`).
 */
import type { IdentityDenialCode } from "@agp/core";
import type {
	ClockPort,
	CredentialVerifier,
	RedeemedAdmissionVerifier,
	RedeemedAdmissionVerifyInput,
	RedeemedAdmissionVerifyResult,
} from "@apnex/caller-identity";
import type { WallClockPort } from "./clock-adapter.js";

export type {
	ClockPort,
	CredentialVerifier,
	IdentityDenialCode,
	RedeemedAdmissionVerifier,
	RedeemedAdmissionVerifyInput,
	RedeemedAdmissionVerifyResult,
	WallClockPort,
};

/** Proof mode for an issued admission key (`A1`, `CIss2`). */
export type AdmissionKeyProofMode = "native-tls13-external-psk-v1" | "bearer";

/** Stored standing-code record (`CIss1`), keeping only the 64-hex SHA-256 `codeHash` and never the raw secret. */
export interface StandingCodeRecord {
	readonly codeId: string;
	readonly codeHash: string;
	readonly identity: string;
	readonly minterPrincipal: string;
	readonly minterIssuer: string;
	readonly createdAtMs: number;
	readonly expiresAtMs: number | null;
	readonly revokedAtMs: number | null;
}

/** Public non-secret standing-code summary returned by `listStandingCodes` (`CIss1`). */
export interface PublicStandingCodeRecord {
	readonly codeId: string;
	readonly identity: string;
	readonly minterPrincipal: string;
	readonly minterIssuer: string;
	readonly createdAtMs: number;
	readonly expiresAtMs: number | null;
	readonly revokedAtMs: number | null;
}

/** Durable or in-memory standing-code store (`CIss1`). */
export interface StandingCodeStore {
	load(): readonly StandingCodeRecord[];
	save(records: readonly StandingCodeRecord[]): void;
}

/** Request to mint a standing code (`CIss1`). */
export interface MintStandingCodeRequest {
	readonly proof: unknown;
	readonly identity: string;
	readonly expiresAtMs?: number | null;
}

/** Result of `mintStandingCode` (`CIss1`). */
export type MintStandingCodeResult =
	| {
			readonly ok: true;
			readonly codeId: string;
			readonly code: string;
			readonly identity: string;
			readonly minterPrincipal: string;
			readonly minterIssuer: string;
			readonly createdAtMs: number;
			readonly expiresAtMs: number | null;
	  }
	| {
			readonly ok: false;
			readonly code:
				| "proof-refused"
				| "invalid-identity"
				| "invalid-expiry"
				| "forbidden-identity"
				| "code-store-unwritable";
	  };

/** Request to list standing codes (`CIss1`). */
export interface ListStandingCodesRequest {
	readonly proof: unknown;
}

/** Result of `listStandingCodes` (`CIss1`). */
export type ListStandingCodesResult =
	| {
			readonly ok: true;
			readonly codes: readonly PublicStandingCodeRecord[];
	  }
	| {
			readonly ok: false;
			readonly code: "proof-refused" | "code-store-unwritable";
	  };

/** Request to revoke a standing code (`CIss1`). */
export interface RevokeStandingCodeRequest {
	readonly proof: unknown;
	readonly codeId: string;
}

/** Result of `revokeStandingCode` (`CIss1`). */
export type RevokeStandingCodeResult =
	| {
			readonly ok: true;
			readonly codeId: string;
			readonly revokedAtMs: number;
	  }
	| {
			readonly ok: false;
			readonly code: "proof-refused" | "not-found" | "code-store-unwritable";
	  };

/** OAuth 2.0-shaped or structured request to issue a single-use admission key (`CIss2`). */
export type IssueAdmissionKeyRequest =
	| {
			readonly grantType: "urn:ietf:params:oauth:grant-type:token-exchange";
			readonly subjectToken: unknown;
			readonly hub: string;
			readonly node: string;
			readonly proofMode?: AdmissionKeyProofMode;
			readonly continuationSecret?: string;
	  }
	| {
			readonly grantType: "client_credentials";
			readonly clientSecret: string;
			readonly hub: string;
			readonly node: string;
			readonly proofMode?: AdmissionKeyProofMode;
			readonly continuationSecret?: string;
	  }
	| {
			readonly proof:
				| { readonly kind: "sign-in"; readonly token: unknown }
				| { readonly kind: "standing-code"; readonly code: string };
			readonly hub: string;
			readonly node: string;
			readonly proofMode?: AdmissionKeyProofMode;
			readonly continuationSecret?: string;
	  };

/** RFC 9068-compatible claims carried on an issued admission key (`CIss2`). */
export interface AdmissionKeyClaims {
	readonly iss: string;
	readonly sub: string;
	readonly aud: string;
	readonly client_id: string;
	readonly jti: string;
	readonly exp: number;
}

/** Issued single-use admission key (`CIss2`, `A1`). */
export interface IssuedAdmissionKey {
	readonly ok: true;
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
	readonly issuedAtMonotonicMs: number;
	readonly validBeforeMonotonicMs: number;
	readonly claims: AdmissionKeyClaims;
}

/** Refusal codes returned by `issueAdmissionKey` (`CIss2`). */
export type IssueAdmissionKeyRefusalCode =
	| "proof-refused"
	| "policy-refused"
	| "node-identity-conflict"
	| "lease-capacity"
	| "wrong-hub"
	| "invalid-node"
	| "invalid-proof-mode"
	| "incompatible-psk-identity"
	| "code-store-unwritable";

/** Result of `issueAdmissionKey` (`CIss2`). */
export type IssueAdmissionKeyResult =
	| IssuedAdmissionKey
	| {
			readonly ok: false;
			readonly code: IssueAdmissionKeyRefusalCode;
	  };

/** Non-secret key-reuse report delivered to `onKeyReuse` (`key-reuse-report`, `CIss3`). */
export interface KeyReuseReport {
	readonly keyFingerprint: string;
	readonly redemptionId: string;
	readonly principal: string;
	readonly issuer: string;
	readonly hub: string;
	readonly node: string;
	readonly firstUseId: string;
	readonly secondUseId: string;
	readonly firstSession: string | null;
	readonly secondSession: string | null;
	readonly firstRedemptionId: string;
	readonly secondRedemptionId: string;
	readonly firstSessionStopped: boolean;
}

/** AGP `AdmissionSessionIdentity` descriptive metadata (`B6`, `D63`, `CIss3`, `CIss4`). */
export interface AdmissionSessionIdentity {
	readonly remoteNodeId: string;
	readonly localSessionId: string;
	readonly authorizationAssociation?: {
		readonly mode: "authenticated";
		readonly issuer: string;
		readonly principal: string;
		readonly instanceBinding: string;
	};
}

/** AGP `AdmissionUseSnapshot` returned by `AdmissionUseObservation.readAdmissionUse()` (`B6`, `D63`, `CIss3`, `CIss4`). */
export type AdmissionUseSnapshot =
	| { readonly state: "pending"; readonly sessionId?: string }
	| {
			readonly state: "admitted" | "established";
			readonly session?: AdmissionSessionIdentity;
			readonly sessionId?: string;
	  }
	| {
			readonly state: "terminal";
			readonly reachedEstablished?: false;
			readonly admittedSession?: never;
			readonly sessionId?: string;
	  }
	| {
			readonly state: "terminal";
			readonly reachedEstablished: boolean;
			readonly admittedSession: AdmissionSessionIdentity;
			readonly sessionId?: string;
	  };

/** AGP `AdmissionUseObservation` lifecycle handle (`B6`, `D63`, `CIss3`, `CIss4`). */
export interface AdmissionUseObservation {
	readAdmissionUse(): AdmissionUseSnapshot | unknown;
}

/** AGP `AdmissionUseControl` handle (`B6`, `D63`, `CIss3`). */
export interface AdmissionUseControl {
	requestAdmissionTermination(): void;
}

/** Result of `AdmissionRedemptionPort.recordAdmissionRedemption` (`B6`, `D63`, `CIss3`). */
export type RecordAdmissionRedemptionResult =
	| {
			readonly kind: "recorded";
			readonly context?: {
				readonly redemptionId: string;
				readonly lifecycle: AdmissionUseObservation;
			};
	  }
	| {
			readonly kind: "refused";
			readonly reason:
				| "inactive"
				| "expired"
				| "authorization-expired"
				| "already-recorded"
				| "invalid-redemption"
				| "invalid-authorization"
				| "capacity";
	  }
	| {
			readonly kind:
				| "authorization-expired"
				| "expired"
				| "invalid-authorization"
				| "invalid-redemption"
				| "inactive"
				| "capacity"
				| "already-recorded";
	  };

/** AGP `AdmissionRedemptionPort` (`B6`, `D63`, `CIss3`). */
export interface AdmissionRedemptionPort {
	recordAdmissionRedemption(
		redemptionId: string,
		authorization: { readonly clock: ClockPort; readonly validBeforeMonotonicMs: number },
	): RecordAdmissionRedemptionResult | unknown;
}

/** AGP `AdmissionUse` reservation handle (`B6`, `A2`, `D63`, `D71`, `D72`, `CIss3`). */
export interface AdmissionUse {
	readonly lifecycle: AdmissionUseObservation;
	readonly control: AdmissionUseControl;
	readonly redemption: AdmissionRedemptionPort;
	sealAdmissionHandoff?(
		channel: object,
	): { readonly kind: "sealed"; readonly handoff: object } | { readonly kind: "refused"; readonly reason?: string };
	finishAdmissionAcquisition?(): void;
}

/** AGP `AdmissionUsePool` passed to `beginPskArrival` (`A2`, `D71`, `D72`, `CIss3`). */
export interface AdmissionUsePool {
	reserveAdmissionUse():
		| { readonly kind: "reserved"; readonly use: AdmissionUse }
		| { readonly kind: "refused"; readonly reason: "capacity" | "inactive" };
}

/** AGP `AdmissionHandoffCallbacks` passed to `beginPskArrival` (`A2`, `D71`, `D72`, `CIss3`). */
export interface AdmissionHandoffCallbacks {
	acceptAdmission(handoff: object): void;
}

/** Result of `resolvePsk` (`preshared-key-secret`, `A2`, `CIss3`). */
export type ResolvePskResult =
	| {
			readonly kind: "resolved";
			readonly secret: Uint8Array;
			readonly lookupRef: object;
	  }
	| {
			readonly kind: "unknown";
	  };

/** Attempt returned by `beginPskArrival` (`A2`, `D71`, `D72`, `CIss3`). */
export interface NativePskProofAttempt {
	readonly kind: "reserved";
	readonly arrival: object;
	readonly use: AdmissionUse;
	resolvePsk(pskIdentity: string): ResolvePskResult;
	completePskProof(proof: { readonly arrival: object; readonly lookupRef: object }): "redeemed" | "refused";
	acceptPskChannel(channel: { close?(): void; dispose?(): void }): void;
	carrierAcquisitionSettled(): void;
	readonly settled: Promise<void>;
}

/** Result of `beginPskArrival` (`A2`, `D71`, `D72`, `CIss3`). */
export type BeginPskArrivalResult =
	| NativePskProofAttempt
	| {
			readonly kind: "refused";
			readonly reason: "capacity" | "inactive";
	  };

/** Redeemer surface embedded in the hub (`CIss3`, `CIss4`). */
export interface CredentialRedeemer extends RedeemedAdmissionVerifier {
	resolvePsk(pskIdentity: string, attempt?: { readonly arrival?: object }): ResolvePskResult;
	completePskProof(
		attempt: { readonly arrival: object; readonly use: AdmissionUse; readonly lookupRef?: object },
		proof: { readonly arrival: object; readonly lookupRef: object },
	): "redeemed" | "refused";
	beginPskArrival(
		uses: AdmissionUsePool,
		callbacks: AdmissionHandoffCallbacks,
		arrival: object,
	): BeginPskArrivalResult;
	redeemBearer(
		use: AdmissionUse,
		bearerToken: string,
		remoteNodeId?: string,
	): "redeemed" | "refused";
	verifyRedeemed(input: RedeemedAdmissionVerifyInput): RedeemedAdmissionVerifyResult;
	sweepLeases(): void;
}

/** Options for `createCredentialIssuer` (`CIss1` to `CIss4`). */
export interface CredentialIssuerOptions {
	readonly hub: string;
	readonly verifiers: readonly CredentialVerifier[];
	readonly standingCodeStore?: StandingCodeStore;
	readonly allowStandingCode?: (input: {
		readonly minterPrincipal: string;
		readonly minterIssuer: string;
		readonly identity: string;
	}) => boolean | Promise<boolean>;
	readonly allowAdmissionKey?: (input: {
		readonly principal: string;
		readonly issuer: string;
		readonly hub: string;
		readonly node: string;
		readonly proofKind: "sign-in" | "standing-code";
		readonly proofMode: AdmissionKeyProofMode;
	}) => boolean | Promise<boolean>;
	readonly isSignInRevoked?: (input: {
		readonly principal: string;
		readonly issuer: string;
		readonly session: string | null;
	}) => boolean | Promise<boolean>;
	readonly onKeyReuse?: (report: KeyReuseReport) => void;
	readonly clock?: ClockPort;
	readonly wallClock?: WallClockPort;
	readonly randomBytes?: (byteLength: number) => Uint8Array;
	readonly keyLifetimeMs?: number;
	readonly keyRetentionMs?: number;
	readonly reconnectGraceMs?: number;
	readonly maxActiveLeases?: number;
	readonly maxHandlesPerLease?: number;
	readonly maxTotalHandles?: number;
	readonly maxRetainedKeys?: number;
	readonly maxPskIdentityBytes?: number;
}

/** Instance returned by `createCredentialIssuer` (`CIss1` to `CIss4`). */
export interface CredentialIssuer extends CredentialRedeemer {
	readonly hub: string;
	readonly generation: string;
	readonly clock: ClockPort;
	readonly redeemer: CredentialRedeemer;
	mintStandingCode(request: MintStandingCodeRequest): Promise<MintStandingCodeResult>;
	listStandingCodes(request: ListStandingCodesRequest): Promise<ListStandingCodesResult>;
	revokeStandingCode(request: RevokeStandingCodeRequest): Promise<RevokeStandingCodeResult>;
	issueAdmissionKey(request: IssueAdmissionKeyRequest): Promise<IssueAdmissionKeyResult>;
}

/** Carrier permit passed to `createCredentialAttempt(request, permit)` (`A3`, `CIss5`). */
export interface CredentialCarrierReservation {
	releaseUnused(): void;
}

/** Primary proof held by a client (`CIss5`). */
export type ClientPrimaryProof =
	| { readonly kind: "sign-in"; readonly token: unknown }
	| { readonly kind: "standing-code"; readonly code: string };

/** Options for `createCredentialPresenterTarget` (`CIss5`, `A3`). */
export interface CredentialPresenterTargetOptions {
	readonly hub: string;
	readonly node: string;
	readonly proofMode?: AdmissionKeyProofMode;
	readonly getProof: () => ClientPrimaryProof;
	readonly issueKey: (
		request: IssueAdmissionKeyRequest,
		signal?: AbortSignal,
	) => IssueAdmissionKeyResult | Promise<IssueAdmissionKeyResult> | unknown;
	readonly connectWithKey: (
		key: {
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
		},
		signal?: AbortSignal,
	) =>
		| Promise<{
				readonly channel?: object;
				readonly socket?: { readonly closed?: Promise<void>; close?(): void };
				readonly transferred?: boolean;
		  }>
		| {
				readonly channel?: object;
				readonly socket?: { readonly closed?: Promise<void>; close?(): void };
				readonly transferred?: boolean;
		  };
	readonly clock?: ClockPort;
}

/** Prepared connection returned by `attempt.prepareCredential` (`CIss5`, `A3`). */
export interface PreparedCredentialConnection {
	connect(signal?: AbortSignal): Promise<{ readonly channel?: object }>;
	markChannelTransferred(): void;
}

/** Result of `attempt.prepareCredential` (`CIss5`, `A3`). */
export type PrepareCredentialResult =
	| {
			readonly kind: "prepared";
			readonly keyMeta: {
				readonly redemptionId: string;
				readonly instanceBinding: string;
				readonly validBeforeMonotonicMs: number;
			};
			readonly connection: PreparedCredentialConnection;
	  }
	| {
			readonly kind: "issuer-refused";
			readonly code: IssueAdmissionKeyRefusalCode;
	  }
	| {
			readonly kind: "issuer-unavailable";
			readonly reason: string;
	  };

/** Attempt returned by `createCredentialAttempt(request, permit)` (`CIss5`, `A3`). */
export interface CredentialAttempt {
	prepareCredential(signal?: AbortSignal): Promise<PrepareCredentialResult>;
	dispose(): Promise<void>;
}

/** Presenter target returned by `createCredentialPresenterTarget` (`CIss5`, `A3`). */
export interface CredentialPresenterTarget {
	readonly hub: string;
	readonly node: string;
	getContinuationSecret(): string | null;
	setContinuationSecret(secret: string | null): void;
	createCredentialAttempt(
		request: { readonly hub?: string; readonly node?: string } | undefined,
		permit: CredentialCarrierReservation,
	): CredentialAttempt;
}

/** Adjacency snapshot item read by `observeAdjacencyRefusal` (`CIss5`, `A4`). */
export interface AdjacencyCredentialSnapshotItem {
	readonly adjacencyId: string;
	readonly adopted?: boolean;
	readonly credential?: {
		readonly phase: "idle" | "preparing" | "prepared" | "issuer-refused" | "issuer-unavailable" | "inactive";
		readonly generation: number;
		readonly code?: string;
	};
}

/** Options for `observeAdjacencyRefusal` (`CIss5`, `A4`). */
export interface AdjacencyRefusalObserverOptions {
	readonly adjacencyId: string;
	readonly events: () =>
		| AsyncIterable<{ readonly type: string; readonly adjacencyId?: string }>
		| {
				subscribe(listener: (event: { readonly type: string; readonly adjacencyId?: string }) => void): {
					unsubscribe(): void;
				};
		  };
	readonly readAdjacencies: () => { readonly items: readonly AdjacencyCredentialSnapshotItem[] } | unknown;
	readonly notifyCredentialChange: (
		adjacencyId: string,
	) =>
		| Promise<{ readonly kind: "committed"; readonly generation: number } | { readonly kind: "inactive" } | unknown>
		| { readonly kind: "committed"; readonly generation: number }
		| { readonly kind: "inactive" }
		| unknown;
	readonly installProof?: (newProof: unknown) => void;
	readonly onAdmissionRefused?: (info: {
		readonly adjacencyId: string;
		readonly generation: number;
		readonly code?: string;
	}) => void;
}

/** Observer returned by `observeAdjacencyRefusal` (`CIss5`, `A4`). */
export interface AdjacencyRefusalObserver {
	getStatus(): {
		readonly admissionRefused: boolean;
		readonly proxyCode: "admission-refused" | null;
		readonly phase: string;
		readonly generation: number;
		readonly code?: string;
	};
	refresh(): {
		readonly admissionRefused: boolean;
		readonly proxyCode: "admission-refused" | null;
		readonly phase: string;
		readonly generation: number;
		readonly code?: string;
	};
	updateProofAndRearm(newProof: unknown): Promise<{
		readonly kind: "committed" | "inactive";
		readonly generation: number;
		readonly status: {
			readonly admissionRefused: boolean;
			readonly proxyCode: "admission-refused" | null;
			readonly phase: string;
			readonly generation: number;
			readonly code?: string;
		};
	}>;
	stop(): void;
}
