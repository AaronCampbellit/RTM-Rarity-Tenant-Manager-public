import * as React from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  /** Modal width in px (640 What-If, 440 Working Set). */
  width?: number;
  children: React.ReactNode;
  className?: string;
}

/** Centered modal over a blurred scrim; `pop` in. Closes on Esc / scrim click. */
export function Dialog({ open, onClose, width = 560, children, className }: DialogProps) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px] animate-fade"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        role="dialog"
        aria-modal="true"
        style={{ width, maxWidth: "100%" }}
        className={cn(
          "animate-pop max-h-[90vh] overflow-y-auto rounded-[14px] border border-[var(--border-strong)] bg-card shadow-[0_24px_70px_rgba(0,0,0,.6)]",
          className,
        )}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}
