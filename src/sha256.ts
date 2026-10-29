/**
 * Runtime-neutral SHA-256, hexadecimal encoding/decoding, UTF-8 encoding, and identifier validation (`CIss1` to `CIss5`).
 */

const K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
	return (x >>> n) | (x << (32 - n));
}

/** Encodes a string into UTF-8 bytes without runtime-specific globals. */
export function utf8Bytes(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

/** Encodes a `Uint8Array` as lowercase hexadecimal digits. */
export function bytesToHex(bytes: Uint8Array): string {
	let out = "";
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i]!.toString(16).padStart(2, "0");
	}
	return out;
}

/** Decodes an even-length lowercase hexadecimal string into a fresh `Uint8Array`, or returns `null` if invalid. */
export function hexToBytes(hex: unknown, expectedByteLength?: number): Uint8Array | null {
	if (typeof hex !== "string") return null;
	if (expectedByteLength !== undefined && hex.length !== expectedByteLength * 2) return null;
	if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return null;
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, "byteLength")!.get!;

/**
 * Validates that `value` is a genuine `Uint8Array` (`Object.getPrototypeOf(value) === Uint8Array.prototype`)
 * with no extra or shadowed own properties (such as a shadowed `byteLength` getter or data property) and
 * exact internal `[[ByteLength]] === expectedByteLength`, returning a fresh `Uint8Array(expectedByteLength)`
 * copy without invoking any getter or `Symbol.iterator` (`F3`, `D54`).
 */
export function readExactUint8Array(value: unknown, expectedByteLength: number): Uint8Array | null {
	if (typeof value !== "object" || value === null) return null;
	try {
		if (Object.getPrototypeOf(value) !== Uint8Array.prototype) return null;
		const actualLen = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, value, []) as number;
		if (actualLen !== expectedByteLength) return null;
		if (Object.getOwnPropertySymbols(value).length > 0) return null;
		const ownNames = Object.getOwnPropertyNames(value);
		if (ownNames.length !== expectedByteLength) return null;
		const out = new Uint8Array(expectedByteLength);
		const src = value as Uint8Array;
		for (let i = 0; i < expectedByteLength; i++) {
			out[i] = src[i]!;
		}
		return out;
	} catch {
		return null;
	}
}

/** Computes the 64-character lowercase hexadecimal SHA-256 digest of a UTF-8 string or `Uint8Array`. */
export function sha256Hex(input: string | Uint8Array): string {
	const msg = typeof input === "string" ? utf8Bytes(input) : input;
	const bitLenHi = Math.floor((msg.length * 8) / 0x100000000);
	const bitLenLo = (msg.length * 8) >>> 0;
	const padLen = ((msg.length + 9 + 63) & ~63);
	const padded = new Uint8Array(padLen);
	padded.set(msg, 0);
	padded[msg.length] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(padLen - 8, bitLenHi, false);
	view.setUint32(padLen - 4, bitLenLo, false);

	let h0 = 0x6a09e667;
	let h1 = 0xbb67ae85;
	let h2 = 0x3c6ef372;
	let h3 = 0xa54ff53a;
	let h4 = 0x510e527f;
	let h5 = 0x9b05688c;
	let h6 = 0x1f83d9ab;
	let h7 = 0x5be0cd19;

	const w = new Uint32Array(64);
	for (let offset = 0; offset < padLen; offset += 64) {
		for (let i = 0; i < 16; i++) {
			w[i] = view.getUint32(offset + i * 4, false);
		}
		for (let i = 16; i < 64; i++) {
			const w15 = w[i - 15]!;
			const w2 = w[i - 2]!;
			const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
			const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
			w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
		}
		let a = h0;
		let b = h1;
		let c = h2;
		let d = h3;
		let e = h4;
		let f = h5;
		let g = h6;
		let h = h7;

		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const temp1 = (h + S1 + ch + K[i]! + w[i]!) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const temp2 = (S0 + maj) >>> 0;

			h = g;
			g = f;
			f = e;
			e = (d + temp1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) >>> 0;
		}

		h0 = (h0 + a) >>> 0;
		h1 = (h1 + b) >>> 0;
		h2 = (h2 + c) >>> 0;
		h3 = (h3 + d) >>> 0;
		h4 = (h4 + e) >>> 0;
		h5 = (h5 + f) >>> 0;
		h6 = (h6 + g) >>> 0;
		h7 = (h7 + h) >>> 0;
	}

	const digest = new Uint8Array(32);
	const outView = new DataView(digest.buffer);
	outView.setUint32(0, h0, false);
	outView.setUint32(4, h1, false);
	outView.setUint32(8, h2, false);
	outView.setUint32(12, h3, false);
	outView.setUint32(16, h4, false);
	outView.setUint32(20, h5, false);
	outView.setUint32(24, h6, false);
	outView.setUint32(28, h7, false);
	return bytesToHex(digest);
}

/**
 * Checks that `value` is a bounded identifier string of 1 to 256 Unicode scalar values (`Array.from(value).length`
 * from 1 to 256) with no control character (`U+0000..U+001F` or `U+007F..U+009F`) and no lone surrogate (`U+D800..U+DFFF`).
 */
export function isValidBoundedIdentifier(value: unknown): value is string {
	if (typeof value !== "string") return false;
	const scalars = Array.from(value);
	if (scalars.length < 1 || scalars.length > 256) return false;
	for (const ch of scalars) {
		const code = ch.codePointAt(0);
		if (code === undefined) return false;
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || (code >= 0xd800 && code <= 0xdfff)) {
			return false;
		}
	}
	return true;
}

/** Checks that `value` is a valid canonical `issuer` namespace (1 to 256 scalar values, never `"agp-transport"`). */
export function isValidIssuer(value: unknown): value is string {
	return isValidBoundedIdentifier(value) && value !== "agp-transport";
}

const IDENTITY_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const NODE_PATTERN = /^([a-z0-9][a-z0-9-]{0,62})\.([0-9a-f]{16})$/;

/** Checks that `value` is a valid machine/proxy identity (`EM1`, `CIss1`). */
export function isValidIdentity(value: unknown): value is string {
	return typeof value === "string" && IDENTITY_PATTERN.test(value);
}

/** Parses a `node` string `<identity>.<16 lowercase hex>` (`PX1`, `D60`, `CIss2`), returning `{ identity, suffix }` or `null`. */
export function parseNodeId(value: unknown): { readonly identity: string; readonly suffix: string } | null {
	if (typeof value !== "string") return null;
	const m = NODE_PATTERN.exec(value);
	if (m === null) return null;
	return { identity: m[1]!, suffix: m[2]! };
}

/** Checks that `value` is a non-empty printable ASCII string (`0x21..0x7E`, no NUL or whitespace) of at most `maxBytes` (`<= 127`) bytes (`A1`). */
export function isValidPrintableAsciiPskIdentity(value: unknown, maxBytes = 127): value is string {
	if (typeof value !== "string" || value.length < 1 || value.length > maxBytes || value.length > 127) {
		return false;
	}
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (code < 0x21 || code > 0x7e) return false;
	}
	return true;
}
