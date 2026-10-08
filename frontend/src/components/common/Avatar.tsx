import { cn } from "@/lib/utils";
import { initials } from "@/lib/utils";

export function Avatar({
  name,
  className,
}: {
  name: string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "grid size-7 shrink-0 place-items-center rounded-full bg-avatar text-[10.5px] font-semibold text-body",
        className,
      )}
    >
      {initials(name)}
    </span>
  );
}
