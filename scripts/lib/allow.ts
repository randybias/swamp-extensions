/** Return the reason in an inline `leak-allow(<reason>)` marker, or null if absent or empty. */
export function allowReason(line: string): string | null {
  const reason = line.match(/leak-allow\(([^)]*)\)/)?.[1].trim();
  return reason ? reason : null;
}
