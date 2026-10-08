import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[8px] text-[13px] font-semibold transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0 cursor-pointer select-none",
  {
    variants: {
      variant: {
        // Secondary control button (#222227 → hover #2b2b32)
        default:
          "bg-[#222227] text-body border border-[var(--border-strong)] hover:bg-[#2b2b32] hover:text-fg",
        // Primary red accent button
        accent:
          "bg-[var(--ac)] text-white border border-transparent hover:brightness-110 shadow-[0_1px_2px_rgba(0,0,0,.4)]",
        ghost: "bg-transparent text-secondary hover:bg-[#222227] hover:text-fg",
        outline:
          "bg-transparent text-body border border-[var(--border-strong)] hover:bg-[#222227]",
        link: "bg-transparent text-[var(--act)] hover:underline px-0",
      },
      size: {
        sm: "h-7 px-2.5 text-[12px]",
        md: "h-9 px-3.5",
        icon: "h-9 w-9 p-0",
      },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";

export { buttonVariants };
