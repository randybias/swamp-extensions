/**
 * Render the nginx site config for one method call.
 *
 * @module
 */

import { renderSite } from "./nginx.ts";
import type { BasicAuthArgs, TlsArgs } from "./schema.ts";

/** Renders the site config for a method's inputs. */
export const renderFor = (
  root: string,
  listen: { address: string; port: number },
  serverName: string,
  tls: TlsArgs,
  basicAuth: BasicAuthArgs | null | undefined,
): string =>
  renderSite({
    root,
    listen,
    serverName,
    tlsProvided: tls.mode === "provided",
    basicAuth: basicAuth != null,
    basicAuthRealm: basicAuth?.realm ?? "",
  });
