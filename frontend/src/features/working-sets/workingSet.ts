/** Keep Working Set targets stable across the mock and live API paths. */
export function normalizeWorkingSetUserIds(userIds: string[]): string[] {
  return [...new Set(userIds.map((id) => id.trim()).filter(Boolean))];
}
