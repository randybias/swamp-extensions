/**
 * Provided-TLS validation, run on the control host before anything is uploaded.
 *
 * The certificate must parse, be valid now, and match the private key. `openssl`
 * is invoked through the injectable command runner, so tests supply canned
 * output and no process is spawned.
 *
 * @module
 */

import { type CommandRunner, SshConfigError } from "./ssh.ts";

/** Dependencies for {@link validateTls}. */
export interface TlsDeps {
  /** Runs local commands. */
  run: CommandRunner;
  /** Current time in milliseconds. */
  now: () => number;
}

/** Parses an `openssl x509 -startdate -enddate` value into epoch milliseconds. */
export function parseOpenSslDate(text: string, label: string): number | null {
  const match = text.match(new RegExp(`${label}=(.+)`));
  if (!match) return null;
  const parsed = Date.parse(match[1].trim());
  return Number.isFinite(parsed) ? parsed : null;
}

/** The base64 body of a PEM block, with headers and whitespace removed. */
export function normalizePem(text: string): string {
  return text
    .split("\n")
    .filter((line) => !line.startsWith("-----"))
    .join("")
    .replace(/\s+/g, "");
}

/**
 * Refuses a certificate or key that does not parse, is not valid now, or does
 * not belong together.
 */
export async function validateTls(
  deps: TlsDeps,
  certPem: string,
  keyPem: string,
): Promise<void> {
  const cert = await deps.run("openssl", ["x509", "-noout"], {
    stdin: certPem,
  });
  if (cert.code !== 0) {
    throw new SshConfigError("cert_pem is not a valid X.509 certificate");
  }
  const key = await deps.run("openssl", ["pkey", "-noout"], { stdin: keyPem });
  if (key.code !== 0) {
    throw new SshConfigError("key_pem is not a valid private key");
  }
  const dates = await deps.run(
    "openssl",
    ["x509", "-noout", "-startdate", "-enddate"],
    { stdin: certPem },
  );
  const notBefore = parseOpenSslDate(dates.stdout, "notBefore");
  const notAfter = parseOpenSslDate(dates.stdout, "notAfter");
  if (notBefore === null || notAfter === null) {
    throw new SshConfigError("could not read the certificate validity dates");
  }
  const now = deps.now();
  if (now < notBefore) throw new SshConfigError("cert_pem is not yet valid");
  if (now > notAfter) throw new SshConfigError("cert_pem is expired");
  const certPub = await deps.run("openssl", ["x509", "-noout", "-pubkey"], {
    stdin: certPem,
  });
  const keyPub = await deps.run("openssl", ["pkey", "-pubout"], {
    stdin: keyPem,
  });
  if (certPub.code !== 0 || keyPub.code !== 0) {
    throw new SshConfigError("could not read the certificate public key");
  }
  if (normalizePem(certPub.stdout) !== normalizePem(keyPub.stdout)) {
    throw new SshConfigError("key_pem does not match cert_pem");
  }
}
