export function threatLockerReadPath(
  suffix: string,
  options: { refresh?: boolean; search?: string } = {},
): string {
  const params = new URLSearchParams();
  if (options.search) params.set("search", options.search);
  if (options.refresh) params.set("refresh", "true");
  const query = params.toString();
  return `/threatlocker${suffix}${query ? `?${query}` : ""}`;
}
