/** RTM wordmark in a rounded red-gradient tile (36px, radius 9). */
export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="grid size-9 place-items-center rounded-[9px] text-[13px] font-bold tracking-tight text-white"
        style={{
          background: "linear-gradient(145deg,#f0565b,#c5343a)",
          boxShadow: "0 2px 8px rgba(229,72,77,.35)",
        }}
      >
        RTM
      </div>
      <div className="leading-tight">
        <div className="text-[14px] font-bold text-fg-strong">Rarity</div>
        <div className="text-[9.5px] font-semibold uppercase tracking-[.8px] text-faint">
          Tenant Manager
        </div>
      </div>
    </div>
  );
}
