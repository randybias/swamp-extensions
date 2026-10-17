/**
 * The one wait shape for every poll and retry loop.
 *
 * The caller's interval is the ceiling, not a fixed beat: the sleep after read
 * number n starts near ceiling/16 and doubles up to the ceiling, with jitter
 * from an injected random source. A poll retries only transport errors;
 * anything else the evaluator raises stops the loop at once. Every loop is
 * bounded by an iteration count as well as the clock, so a frozen test clock
 * cannot spin forever, and one final read runs after the deadline.
 *
 * @module
 */

import { TransportError } from "./errors.ts";

/** Dependencies a wait needs; all injected so tests need no real clock. */
export interface WaitDeps {
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
  /** Random value in [0, 1). */
  random: () => number;
}

/**
 * The capped exponential sleep for zero-based index `n` with ceiling `ceiling`.
 * r = 0 gives half the raw value; r approaching 1 gives the raw value.
 */
export function cappedBackoff(n: number, ceiling: number, r: number): number {
  const c = Math.max(1, ceiling);
  const base = Math.max(1, Math.ceil(c / 16));
  const raw = Math.max(1, Math.min(c, base * 2 ** n));
  const jitter = Math.min(0.999999, Math.max(0, r));
  return Math.max(1, Math.round(raw / 2 + jitter * (raw / 2)));
}

/** Options for {@link poll}. */
export interface PollOptions<T> {
  /** Absolute deadline in milliseconds on the injected clock. */
  deadlineMs: number;
  /** Longest gap between reads, in milliseconds. */
  ceilingMs: number;
  /** Reads and evaluates once; may throw a {@link TransportError} to retry. */
  read: () => Promise<T>;
  /** Returns true when the read is the success state; may throw to stop at once. */
  done: (value: T) => boolean;
  /** Hard iteration bound, independent of the clock. */
  maxIterations?: number;
  /** Called when a transport error is retried. */
  onTransportError?: (e: TransportError, attempt: number) => void;
}

/** Outcome of {@link poll}: the last read and the number of reads made. */
export interface PollResult<T> {
  /** The last value read, or null when the evaluator never accepted one. */
  value: T | null;
  /** Number of reads actually made. */
  attempts: number;
}

/**
 * Reads until `done` accepts, the deadline passes, or the iteration bound is
 * hit. Transport errors are retried; any other error propagates at once. One
 * final read always runs after the deadline.
 */
export async function poll<T>(
  deps: WaitDeps,
  opts: PollOptions<T>,
): Promise<PollResult<T>> {
  const maxIterations = opts.maxIterations ?? 10_000;
  let attempts = 0;

  const readOnce = async (): Promise<T | null> => {
    attempts++;
    try {
      return await opts.read();
    } catch (e) {
      if (e instanceof TransportError) {
        opts.onTransportError?.(e, attempts);
        return null;
      }
      throw e;
    }
  };

  for (let i = 0; i < maxIterations; i++) {
    const value = await readOnce();
    if (value !== null && opts.done(value)) return { value, attempts };
    if (deps.now() >= opts.deadlineMs) break;
    const remaining = opts.deadlineMs - deps.now();
    if (remaining <= 0) break;
    const wait = Math.min(
      remaining,
      cappedBackoff(i, opts.ceilingMs, deps.random()),
    );
    await deps.sleep(wait);
  }

  // A read that raced the deadline still counts: try once more.
  const finalValue = await readOnce();
  if (finalValue !== null && opts.done(finalValue)) {
    return { value: finalValue, attempts };
  }
  return { value: null, attempts };
}
