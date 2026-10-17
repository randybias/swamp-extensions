/**
 * The bogworks test harness: a recording fake for the canonical SSH transport
 * with secret assertions and script capture, builders for the canonical remote
 * shell shape, and docker helpers for real-tool validation. Each file is
 * self-contained so extensions vendor them byte-identical (see README.md).
 *
 * @module
 */

export * from "./recording-runner.ts";
export * from "./remote-script.ts";
export * from "./containers.ts";
