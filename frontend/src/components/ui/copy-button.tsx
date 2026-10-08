import { useEffect, useState } from "react";
import { AlertTriangle, Check, Copy } from "lucide-react";
import { copyText } from "@/lib/clipboard";
import { Button } from "./button";

type CopyStatus = "idle" | "copied" | "error";

/** Shared copy control with honest success/failure feedback. */
export function CopyButton({ value }: { value: string }) {
  const [status, setStatus] = useState<CopyStatus>("idle");

  useEffect(() => {
    if (status === "idle") return;
    const timer = window.setTimeout(() => setStatus("idle"), 2500);
    return () => window.clearTimeout(timer);
  }, [status]);

  async function copy() {
    try {
      await copyText(value);
      setStatus("copied");
    } catch {
      setStatus("error");
    }
  }

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      onClick={copy}
      aria-live="polite"
      title={status === "error" ? "Clipboard access failed. Try selecting and copying the value manually." : undefined}
    >
      {status === "copied" ? (
        <Check className="size-3.5" />
      ) : status === "error" ? (
        <AlertTriangle className="size-3.5" />
      ) : (
        <Copy className="size-3.5" />
      )}
      {status === "copied" ? "Copied" : status === "error" ? "Copy failed" : "Copy"}
    </Button>
  );
}
