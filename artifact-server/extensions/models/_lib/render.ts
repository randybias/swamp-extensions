/**
 * Render the nginx site config for one method call.
 *
 * @module
 */

import { renderSite } from "./nginx.ts";
import type { BasicAuthArgs, TlsArgs } from "./schema.ts";

/** The inputs {@link renderFor} draws from a method's arguments. */
export interface RenderInput {
  root: string;
  listen: { address: string; port: number };
  server_name: string;
  tls: TlsArgs;
  basic_auth?: BasicAuthArgs | null;
}

/** Renders the site config for a method's inputs. */
export function renderFor(args: RenderInput): string {
  return renderSite({
    root: args.root,
    listen: args.listen,
    serverName: args.server_name,
    tlsProvided: args.tls.mode === "provided",
    basicAuth: args.basic_auth != null,
    basicAuthRealm: args.basic_auth?.realm ?? "",
  });
}
