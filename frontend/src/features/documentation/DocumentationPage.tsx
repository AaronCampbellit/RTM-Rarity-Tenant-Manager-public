import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CircleAlert,
  ExternalLink,
  Info,
  Maximize2,
  SearchX,
  ShieldCheck,
  X,
} from "lucide-react";
import { useSetPageTitle } from "@/store/page";
import { SearchInput } from "@/components/ui/input";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import {
  DOCUMENTATION_GUIDES,
  DOCUMENTATION_SECTION_ORDER,
  START_STEPS,
  documentationGuideSearchText,
  type CalloutTone,
  type DocumentationBlock,
  type DocumentationGuide,
} from "./documentationContent";

const CALLOUT_STYLE: Record<CalloutTone, string> = {
  info: "border-info/30 bg-info/10",
  success: "border-success/30 bg-success/10",
  warning: "border-warning/30 bg-warning/10",
  danger: "border-danger/30 bg-danger/10",
};

const CALLOUT_ICON: Record<CalloutTone, typeof Info> = {
  info: Info,
  success: ShieldCheck,
  warning: CircleAlert,
  danger: AlertTriangle,
};

const CALLOUT_ICON_STYLE: Record<CalloutTone, string> = {
  info: "text-info",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
};

export function DocumentationPage() {
  useSetPageTitle("Documentation");
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedGuide = searchParams.get("guide");
  const queryFromUrl = searchParams.get("q") ?? "";
  const [query, setQuery] = useState(queryFromUrl);
  const articleRef = useRef<HTMLElement>(null);

  useEffect(() => setQuery(queryFromUrl), [queryFromUrl]);

  const activeGuide =
    DOCUMENTATION_GUIDES.find((guide) => guide.slug === requestedGuide) ??
    DOCUMENTATION_GUIDES.find((guide) => guide.slug === "getting-started")!;

  const filteredGuides = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return DOCUMENTATION_GUIDES;
    return DOCUMENTATION_GUIDES.filter((guide) => documentationGuideSearchText(guide).includes(normalized));
  }, [query]);

  const anchors = useMemo(
    () => [
      { id: `doc-${activeGuide.slug}-overview`, title: "Overview" },
      ...activeGuide.blocks.flatMap((block) =>
        block.type === "heading"
          ? [{ id: `doc-${activeGuide.slug}-${block.id}`, title: block.title }]
          : [],
      ),
    ],
    [activeGuide],
  );

  function selectGuide(slug: string) {
    const next = new URLSearchParams(searchParams);
    next.set("guide", slug);
    next.delete("q");
    setSearchParams(next);
    setQuery("");
    requestAnimationFrame(() => articleRef.current?.scrollIntoView({ block: "start" }));
  }

  return (
    <div className="-mx-4 -my-4 min-h-[calc(100vh-58px)] sm:-mx-6 sm:-my-[22px]">
      <div className="grid min-h-[calc(100vh-58px)] lg:grid-cols-[224px_minmax(0,1fr)] xl:grid-cols-[224px_minmax(0,1fr)_178px]">
        <GuideRail
          activeGuide={activeGuide}
          guides={filteredGuides}
          query={query}
          onQueryChange={setQuery}
          onSelect={selectGuide}
        />

        <main className="min-w-0 border-[var(--border-card)] lg:border-l">
          <GuideHero onSelectGuide={selectGuide} />
          <article
            ref={articleRef}
            key={activeGuide.slug}
            id={`doc-${activeGuide.slug}-overview`}
            className="animate-fade scroll-mt-4 px-5 py-7 sm:px-8 lg:px-10"
          >
            <ArticleHeader guide={activeGuide} />
            <div className="mt-6 space-y-5">
              {activeGuide.blocks.map((block, index) => (
                <DocumentationBlockView
                  key={`${activeGuide.slug}-${block.type}-${index}`}
                  block={block}
                  guideSlug={activeGuide.slug}
                />
              ))}
            </div>
          </article>
        </main>

        <OnThisGuide anchors={anchors} />
      </div>
    </div>
  );
}

function GuideRail({
  activeGuide,
  guides,
  query,
  onQueryChange,
  onSelect,
}: {
  activeGuide: DocumentationGuide;
  guides: DocumentationGuide[];
  query: string;
  onQueryChange: (value: string) => void;
  onSelect: (slug: string) => void;
}) {
  return (
    <aside
      aria-label="Documentation guides"
      className="border-b border-[var(--border-card)] bg-header/35 px-4 py-4 lg:sticky lg:top-0 lg:h-[calc(100vh-58px)] lg:overflow-y-auto lg:border-b-0"
    >
      <SearchInput
        aria-label="Search guides"
        placeholder="Search guides…"
        value={query}
        onChange={(event) => onQueryChange(event.target.value)}
      />

      <div className="mt-3 lg:hidden">
        <label htmlFor="documentation-guide" className="sr-only">
          Select a documentation guide
        </label>
        <select
          id="documentation-guide"
          value={activeGuide.slug}
          onChange={(event) => onSelect(event.target.value)}
          className="h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]"
        >
          {DOCUMENTATION_SECTION_ORDER.map((section) => (
            <optgroup key={section} label={section}>
              {DOCUMENTATION_GUIDES.filter((guide) => guide.section === section).map((guide) => (
                <option key={guide.slug} value={guide.slug}>
                  {guide.title}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
      </div>

      <nav className="mt-4 hidden space-y-4 lg:block">
        {DOCUMENTATION_SECTION_ORDER.map((section) => {
          const sectionGuides = guides.filter((guide) => guide.section === section);
          if (sectionGuides.length === 0) return null;
          return (
            <div key={section}>
              <p className="mb-1 px-2.5 text-[9.5px] font-bold uppercase tracking-[.7px] text-faint">
                {section}
              </p>
              <div className="space-y-0.5">
                {sectionGuides.map((guide) => (
                  <GuideRailButton
                    key={guide.slug}
                    guide={guide}
                    active={guide.slug === activeGuide.slug}
                    onSelect={onSelect}
                  />
                ))}
              </div>
            </div>
          );
        })}

        {guides.length === 0 && (
          <div className="px-2 py-8 text-center">
            <SearchX className="mx-auto size-5 text-faint" />
            <p className="mt-2 text-[12px] font-semibold text-secondary">No guides match</p>
            <button
              type="button"
              className="mt-1 text-[12px] text-[var(--act)] hover:underline"
              onClick={() => onQueryChange("")}
            >
              Clear search
            </button>
          </div>
        )}
      </nav>
    </aside>
  );
}

function GuideRailButton({
  guide,
  active,
  onSelect,
}: {
  guide: DocumentationGuide;
  active: boolean;
  onSelect: (slug: string) => void;
}) {
  const Icon = guide.icon;
  return (
    <button
      type="button"
      onClick={() => onSelect(guide.slug)}
      className={cn(
        "flex w-full items-start gap-2.5 rounded-[7px] border-l-2 px-2.5 py-2 text-left text-[12.5px] transition-colors",
        active
          ? "border-[var(--ac)] bg-[var(--acb)] font-semibold text-[var(--act)]"
          : "border-transparent text-body hover:bg-white/[.035] hover:text-fg",
      )}
    >
      <Icon className={cn("mt-px size-4 shrink-0", active ? "text-[var(--ac)]" : "text-faint")} />
      <span>{guide.title}</span>
    </button>
  );
}

function GuideHero({ onSelectGuide }: { onSelectGuide: (slug: string) => void }) {
  return (
    <section className="border-b border-[var(--border-card)] px-5 py-7 sm:px-8 lg:px-10">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-[27px] font-bold tracking-[-0.02em] text-fg-strong">
            RTM operator guide
          </h2>
          <p className="mt-1 max-w-[700px] text-[13.5px] leading-6 text-secondary">
            Everything technicians and administrators need to connect tenants,
            investigate risk, and make safe changes.
          </p>
        </div>
        <p className="text-[11.5px] text-muted">
          {DOCUMENTATION_GUIDES.length} guides · Updated August 26, 2026
        </p>
      </div>

      <div className="mt-5 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold text-fg">Start here</h3>
        <span className="hidden text-[11.5px] text-faint sm:inline">A safe path through every write</span>
      </div>
      <div className="-mx-5 mt-2 flex snap-x gap-2.5 overflow-x-auto px-5 pb-1 sm:mx-0 sm:grid sm:grid-cols-2 sm:overflow-visible sm:px-0 sm:pb-0 xl:grid-cols-4">
        {START_STEPS.map((step) => (
          <button
            key={step.number}
            type="button"
            onClick={() => onSelectGuide(step.guide)}
            className="group flex min-h-[92px] min-w-[245px] snap-start items-start gap-3 rounded-[10px] border border-[var(--border-card)] bg-card px-3.5 py-3 text-left transition-colors hover:border-[var(--border-strong)] hover:bg-raised focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ac)] sm:min-w-0"
          >
            <span className="grid size-6 shrink-0 place-items-center rounded-full bg-info text-[11px] font-bold text-white">
              {step.number}
            </span>
            <span className="min-w-0">
              <span className="flex items-center gap-1 text-[12.5px] font-semibold text-fg">
                {step.title}
                <ArrowRight className="size-3.5 text-faint transition-transform group-hover:translate-x-0.5" />
              </span>
              <span className="mt-1 block text-[11.5px] leading-[1.45] text-muted">
                {step.detail}
              </span>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

function ArticleHeader({ guide }: { guide: DocumentationGuide }) {
  const Icon = guide.icon;
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="flex min-w-0 items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-[10px] border border-[var(--border-card)] bg-raised">
          <Icon className="size-[18px] text-[var(--act)]" />
        </span>
        <div>
          <h2 className="text-[22px] font-bold tracking-[-0.015em] text-fg-strong">
            {guide.title}
          </h2>
          <p className="mt-1 max-w-[720px] text-[13px] leading-5 text-secondary">
            {guide.description}
          </p>
        </div>
      </div>
      {guide.route && (
        <Link
          to={guide.route}
          className={buttonVariants({ variant: "default", size: "sm" })}
        >
          {guide.routeLabel ?? "Open workspace"}
          <ExternalLink className="size-3.5" />
        </Link>
      )}
    </div>
  );
}

function DocumentationBlockView({
  block,
  guideSlug,
}: {
  block: DocumentationBlock;
  guideSlug: string;
}) {
  switch (block.type) {
    case "paragraph":
      return <p className="max-w-[820px] text-[13.5px] leading-6 text-body">{block.text}</p>;
    case "heading":
      return (
        <h3
          id={`doc-${guideSlug}-${block.id}`}
          className="scroll-mt-5 border-t border-[var(--border-card)] pt-6 text-[16px] font-bold text-fg-strong"
        >
          {block.title}
        </h3>
      );
    case "bullets":
      return (
        <ul className="max-w-[820px] space-y-2.5">
          {block.items.map((item) => (
            <li key={item} className="flex items-start gap-2.5 text-[13px] leading-5 text-body">
              <Check className="mt-0.5 size-4 shrink-0 text-success" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      );
    case "steps":
      return (
        <ol className="grid gap-px overflow-hidden rounded-[10px] border border-[var(--border-card)] bg-[var(--border-card)] md:grid-cols-2 xl:grid-cols-4">
          {block.items.map((item, index) => (
            <li key={item.title} className="bg-card p-3.5">
              <div className="flex items-center gap-2">
                <span className="grid size-5 place-items-center rounded-full border border-info/40 bg-info/10 text-[10px] font-bold text-info">
                  {index + 1}
                </span>
                <p className="text-[12.5px] font-semibold text-fg">{item.title}</p>
              </div>
              <p className="mt-2 text-[11.5px] leading-[1.5] text-muted">{item.detail}</p>
            </li>
          ))}
        </ol>
      );
    case "callout":
      return <DocumentationCallout {...block} />;
    case "screenshot":
      return <ScreenshotFigure {...block} />;
    case "table":
      return <DocumentationTable columns={block.columns} rows={block.rows} />;
  }
}

function DocumentationCallout({
  tone,
  title,
  body,
}: {
  tone: CalloutTone;
  title: string;
  body: string;
}) {
  const Icon = CALLOUT_ICON[tone];
  return (
    <div className={cn("flex max-w-[880px] items-start gap-3 rounded-[10px] border px-3.5 py-3", CALLOUT_STYLE[tone])}>
      <Icon className={cn("mt-0.5 size-[18px] shrink-0", CALLOUT_ICON_STYLE[tone])} />
      <div>
        <p className="text-[12.5px] font-semibold text-fg">{title}</p>
        <p className="mt-0.5 text-[12px] leading-5 text-secondary">{body}</p>
      </div>
    </div>
  );
}

function DocumentationTable({ columns, rows }: { columns: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto rounded-[10px] border border-[var(--border-card)]">
      <table className={cn("w-full border-collapse text-left", columns.length >= 5 ? "min-w-[980px]" : "min-w-[620px]")}>
        <thead className="bg-th">
          <tr>
            {columns.map((column) => (
              <th
                key={column}
                className="border-b border-[var(--border-card)] px-3.5 py-2.5 text-[10.5px] font-bold uppercase tracking-[.45px] text-faint"
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border-card)] bg-card">
          {rows.map((row, rowIndex) => (
            <tr key={`${row[0]}-${rowIndex}`} className="align-top hover:bg-[var(--row-hover)]">
              {row.map((cell, cellIndex) => (
                <td
                  key={`${cellIndex}-${cell}`}
                  className={cn(
                    "px-3.5 py-3 text-[12px] leading-[1.45]",
                    cellIndex === 0 ? "font-semibold text-fg" : "text-secondary",
                  )}
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScreenshotFigure({
  src,
  alt,
  title,
  caption,
}: {
  src: string;
  alt: string;
  title: string;
  caption: string;
}) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <figure className="overflow-hidden rounded-[11px] border border-[var(--border-strong)] bg-card">
        <button
          type="button"
          className="group relative block w-full overflow-hidden bg-app text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--ac)]"
          aria-label={`Expand screenshot: ${title}`}
          onClick={() => setExpanded(true)}
        >
          <img
            src={src}
            alt={alt}
            loading="lazy"
            className="aspect-[16/10] w-full object-cover object-top transition-transform duration-300 group-hover:scale-[1.01]"
          />
          <span className="absolute right-3 top-3 inline-flex items-center gap-1.5 rounded-[7px] border border-[var(--border-strong)] bg-header/90 px-2.5 py-1.5 text-[11px] font-semibold text-body opacity-0 backdrop-blur transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
            <Maximize2 className="size-3.5" /> Expand
          </span>
        </button>
        <figcaption className="border-t border-[var(--border-card)] px-4 py-3">
          <p className="text-[12.5px] font-semibold text-fg">{title}</p>
          <p className="mt-0.5 text-[11.5px] leading-5 text-muted">{caption}</p>
        </figcaption>
      </figure>

      <Dialog open={expanded} onClose={() => setExpanded(false)} width={1180} className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
          <div>
            <p className="text-[13px] font-semibold text-fg">{title}</p>
            <p className="text-[11.5px] text-muted">Mock environment · example data</p>
          </div>
          <Button variant="ghost" size="icon" aria-label="Close screenshot" onClick={() => setExpanded(false)}>
            <X className="size-4" />
          </Button>
        </div>
        <img src={src} alt={alt} className="h-auto w-full" />
      </Dialog>
    </>
  );
}

function OnThisGuide({ anchors }: { anchors: Array<{ id: string; title: string }> }) {
  return (
    <aside className="hidden border-l border-[var(--border-card)] px-5 py-8 xl:block">
      <nav aria-label="On this guide" className="sticky top-6">
        <p className="text-[10px] font-bold uppercase tracking-[.7px] text-faint">On this guide</p>
        <div className="mt-3 space-y-1">
          {anchors.map((anchor, index) => (
            <button
              key={anchor.id}
              type="button"
              onClick={() => document.getElementById(anchor.id)?.scrollIntoView({ behavior: "smooth", block: "start" })}
              className={cn(
                "block w-full rounded-[6px] px-2 py-1.5 text-left text-[11.5px] leading-4 transition-colors hover:bg-white/[.035] hover:text-fg",
                index === 0 ? "font-semibold text-[var(--act)]" : "text-muted",
              )}
            >
              {anchor.title}
            </button>
          ))}
        </div>
      </nav>
    </aside>
  );
}
