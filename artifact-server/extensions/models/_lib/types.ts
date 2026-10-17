/**
 * Shared model types: the subset of the swamp method context this model uses,
 * and the shape of the model definition itself.
 *
 * @module
 */

import type { z } from "npm:zod@4.3.6";

/** A handle returned by `writeResource`. */
export interface DataHandle {
  /** Data artifact name. */
  name: string;
  /** Declared resource spec name. */
  specName: string;
  /** `"resource"` or `"file"`. */
  kind: string;
  /** Unique data id. */
  dataId: string;
  /** Version number of this write. */
  version: number;
  /** Size of the written content in bytes. */
  size: number;
}

/** What a method returns to swamp. */
export interface MethodResult {
  /** Resources written by the method. */
  dataHandles?: DataHandle[];
  /** Typed result for the caller / workflow. */
  result?: unknown;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  /** Structured logger provided by swamp. */
  logger: {
    /** Logs at info level. */
    info: (message: string, fields?: Record<string, unknown>) => void;
    /** Logs at warn level. */
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  /** Persists one resource and returns its handle. */
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  /** Reads the latest version of one stored resource, or null. */
  readResource?: (
    instanceName: string,
  ) => Promise<Record<string, unknown> | null>;
}

/** A resource specification exposed by the model. */
export interface ResourceSpec {
  /** Human-readable description of the resource. */
  description: string;
  /** Zod schema the resource data is validated against. */
  schema: z.ZodType;
  /** Retention lifetime. */
  lifetime: string;
  /** Number of versions to keep. */
  garbageCollection: number;
}

/** A method exposed by the model. */
export interface ArtifactServerMethod {
  /** `action` for a mutating verb; never a bare `delete`. */
  kind?: "action";
  /** One to three sentences, with the READ-ONLY or DESTRUCTIVE lead. */
  description: string;
  /** Zod schema for the method arguments. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface ArtifactServerModel {
  /** Model type. */
  type: string;
  /** CalVer version, matching the manifest. */
  version: string;
  /** One-line summary for `swamp model type describe`. */
  description: string;
  /** Empty: every method takes its own target. */
  globalArguments: z.ZodType;
  /** Resource specifications. */
  resources: Record<string, ResourceSpec>;
  /** Method implementations. */
  methods: Record<string, ArtifactServerMethod>;
}
