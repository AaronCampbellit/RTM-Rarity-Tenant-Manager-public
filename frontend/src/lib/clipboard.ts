export interface CopyTextDependencies {
  clipboard?: Pick<Clipboard, "writeText"> | null;
  document?: Pick<Document, "activeElement" | "body" | "createElement" | "execCommand"> | null;
}

/**
 * Copy text in both secure contexts and RTM's HTTP demo environment.
 *
 * The async Clipboard API is intentionally tried first. Browsers commonly
 * hide or reject it on plain HTTP, so the temporary-textarea path preserves a
 * working copy action until the demo is served over HTTPS.
 */
export async function copyText(
  value: string,
  dependencies?: CopyTextDependencies,
): Promise<void> {
  const clipboard = dependencies
    ? dependencies.clipboard
    : typeof navigator === "undefined"
      ? undefined
      : navigator.clipboard;
  const clipboardDocument = dependencies
    ? dependencies.document
    : typeof document === "undefined"
      ? undefined
      : document;

  if (clipboard?.writeText) {
    try {
      await clipboard.writeText(value);
      return;
    } catch {
      // Permission and insecure-context failures fall through to the legacy
      // copy command, which still works for direct user gestures over HTTP.
    }
  }

  if (!clipboardDocument?.body || !clipboardDocument.execCommand) {
    throw new Error("Clipboard access is unavailable in this browser.");
  }

  const previousFocus = clipboardDocument.activeElement as HTMLElement | null;
  const textarea = clipboardDocument.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.inset = "0 auto auto -9999px";
  textarea.style.opacity = "0";
  clipboardDocument.body.appendChild(textarea);

  try {
    textarea.focus({ preventScroll: true });
    textarea.select();
    textarea.setSelectionRange(0, value.length);
    if (!clipboardDocument.execCommand("copy")) {
      throw new Error("The browser rejected the clipboard operation.");
    }
  } finally {
    textarea.remove();
    try {
      previousFocus?.focus({ preventScroll: true });
    } catch {
      // Copy succeeded; failure to restore a removed control is harmless.
    }
  }
}
