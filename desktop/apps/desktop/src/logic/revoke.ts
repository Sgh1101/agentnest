/** Device revoke confirmation: the user must type the exact device name (security.md 10). */
export function revokeNameMatches(expectedName: string, typed: string): boolean {
  if (expectedName.length === 0) return false;
  return typed.normalize("NFC") === expectedName.normalize("NFC");
}
