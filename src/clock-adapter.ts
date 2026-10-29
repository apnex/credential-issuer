/**
 * Runtime clock, wall-clock and cryptographic randomness adapters (`CIss1`, `CIss2`, `D31`, Principle 6).
 *
 * Confined to a file whose name ends `-adapter.ts` so runtime-neutral source files never read a clock, set a
 * timer or call a randomness global directly.
 */
import type { Cancellable, ClockPort } from "@apnex/caller-identity";

export type { Cancellable, ClockPort };

/** Restart-stable wall-clock port in milliseconds since the Unix epoch, used for standing-code timestamps (`CIss1`). */
export interface WallClockPort {
	nowMs(): number;
}

/**
 * The default monotonic clock (`performance.now()` and `setTimeout`), waking only once the requested delay has
 * passed on `performance.now()`.
 */
export const defaultClock: ClockPort = Object.freeze({
	now(): number {
		return performance.now();
	},
	schedule(delayMs: number, callback: () => void): Cancellable {
		const dueAt = performance.now() + delayMs;
		let handle: ReturnType<typeof setTimeout>;
		const wake = (): void => {
			const now = performance.now();
			if (now < dueAt) {
				handle = setTimeout(wake, Math.ceil(dueAt - now));
				return;
			}
			callback();
		};
		handle = setTimeout(wake, delayMs);
		return Object.freeze({
			cancel(): void {
				clearTimeout(handle);
			},
		});
	},
});

/** The default wall-clock port (`Date.now()`). */
export const defaultWallClock: WallClockPort = Object.freeze({
	nowMs(): number {
		return Date.now();
	},
});

/** The default cryptographically secure random byte generator (`globalThis.crypto.getRandomValues`). */
export function defaultRandomBytes(byteLength: number): Uint8Array {
	const out = new Uint8Array(byteLength);
	globalThis.crypto.getRandomValues(out);
	return out;
}
