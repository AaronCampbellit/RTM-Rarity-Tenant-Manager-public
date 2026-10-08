import { useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  FileArchive,
  FileJson,
  FolderSearch,
  GitBranch,
  ListChecks,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UploadCloud,
} from "lucide-react";

import { api } from "@/api/client";
import { useRefreshingAsync } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Input, SearchInput } from "@/components/ui/input";
import { UnderlineTabs } from "@/components/ui/tabs";
import { contributingStorylineDetections, primaryStorylineEntity, storylineDuration, storylineNarrative } from "@/features/offline-investigations/storyline-presentation";
import { filterTimelineEvents, groupTimelineEvents, timelineWorkloads, type TimelineActivityGroup, type TimelineFocus } from "@/features/offline-investigations/timeline";
import { OFFLINE_EVIDENCE_MAX_FILE_BYTES } from "@/lib/offline-investigation-limits";
import { cn } from "@/lib/utils";
import { useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import type {
  OfflineEvidenceCoverage,
  OfflineInvestigation,
  OfflineInvestigationDetail,
  OfflineInvestigationFile,
  OfflineTimelineEvent,
  SecurityNativeDetection,
  SecurityStoryline,
  StatusTone,
} from "@/types";

const CASE_TABS = [
  { key: "overview", label: "Overview" },
  { key: "timeline", label: "Timeline" },
  { key: "detections", label: "Detections" },
  { key: "evidence", label: "Evidence" },
];

const TIMELINE_SELECT_CLASS = "h-9 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12.5px] text-body outline-none focus:border-[var(--ac)]/50";

export function OfflineInvestigationsPage() {
  const { id } = useParams();
  useSetPageTitle(id ? "Offline Investigation" : "Offline Investigations");
  return id ? <InvestigationWorkspace id={id} /> : <InvestigationList />;
}

function InvestigationList() {
  const navigate = useNavigate();
  const [createOpen, setCreateOpen] = useState(false);
  const [search, setSearch] = useState("");
  const query = useRefreshingAsync(() => api.security.offlineInvestigations(), [], {
    cacheKey: "offline-investigations:list",
  });
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (query.data ?? []).filter((item) => !needle || `${item.name} ${item.tenantLabel} ${item.status}`.toLowerCase().includes(needle));
  }, [query.data, search]);

  return (
    <div className="space-y-4">
      <section className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-3xl">
          <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[.12em] text-faint">
            <FolderSearch className="size-4 text-info" /> Forensic workspace
          </div>
          <h2 className="text-[22px] font-bold text-fg-strong">Investigate exported Microsoft 365 evidence</h2>
          <p className="mt-1.5 text-[13px] leading-5 text-muted">
            Upload tenant exports, run RTM&apos;s detection packs, and reconstruct a case timeline without connecting the tenant or affecting the live incident queue.
          </p>
        </div>
        <Button variant="accent" onClick={() => setCreateOpen(true)}><Plus /> New investigation</Button>
      </section>

      <div className="rounded-[10px] border border-info/20 bg-info/5 px-4 py-3 text-[12.5px] text-secondary">
        <span className="font-semibold text-info">Isolated evidence:</span> uploaded logs, derived detections, and storylines remain inside their case. Offline cases are read-only analysis and never create live incidents or enable remediation actions.
      </div>

      <div className="flex items-center gap-3">
        <SearchInput className="max-w-[420px] flex-1" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search case or tenant…" />
        <Button size="icon" aria-label="Refresh cases" onClick={query.refresh} disabled={query.refreshing}><RefreshCw className={cn(query.refreshing && "animate-spin")} /></Button>
      </div>

      <Card className="overflow-hidden">
        <div className="hidden grid-cols-[minmax(0,1.8fr)_minmax(140px,.8fr)_110px_100px_92px_22px] gap-3 border-b border-[var(--border-card)] bg-th px-4 py-2.5 text-[10.5px] font-bold uppercase tracking-[.06em] text-faint md:grid">
          <span>Investigation</span><span>Tenant label</span><span>Status</span><span>Evidence</span><span>Updated</span><span />
        </div>
        {query.loading ? <CenteredState icon={<Loader2 className="animate-spin" />} label="Loading investigations…" />
          : query.error ? <CenteredState icon={<AlertTriangle className="text-danger" />} label={query.error.message} />
            : rows.length === 0 ? <CenteredState icon={<FileArchive />} label={search ? "No investigations match this search." : "No offline investigations yet."} />
              : rows.map((item) => (
                <button key={item.id} onClick={() => navigate(`/offline-investigations/${item.id}`)} className="grid w-full gap-3 border-b border-[var(--border-card)] px-4 py-3 text-left transition-colors last:border-0 hover:bg-[var(--row-hover)] md:grid-cols-[minmax(0,1.8fr)_minmax(140px,.8fr)_110px_100px_92px_22px] md:items-center">
                  <span className="min-w-0"><span className="block truncate text-[13px] font-semibold text-fg">{item.name}</span><span className="mt-0.5 block truncate text-[11.5px] text-muted">Created by {item.createdBy}</span></span>
                  <span className="text-[12.5px] text-body">{item.tenantLabel}</span>
                  <span><CaseStatus status={item.status} progress={item.progress} /></span>
                  <span className="tabular text-[12.5px] text-secondary">{item.eventCount ? `${item.eventCount.toLocaleString()} events` : "Not analyzed"}</span>
                  <span className="text-[12px] text-muted">{relativeTime(item.updatedAt)}</span>
                  <ChevronRight className="hidden size-4 text-faint md:block" />
                </button>
              ))}
      </Card>
      <CreateInvestigationDialog open={createOpen} onClose={() => setCreateOpen(false)} onCreated={(investigation) => navigate(`/offline-investigations/${investigation.id}`)} />
    </div>
  );
}

function CreateInvestigationDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (item: OfflineInvestigation) => void }) {
  const [name, setName] = useState("");
  const [tenantLabel, setTenantLabel] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim() || !tenantLabel.trim()) return;
    setSaving(true); setError("");
    try {
      const investigation = await api.security.createOfflineInvestigation({ name: name.trim(), tenantLabel: tenantLabel.trim() });
      setName(""); setTenantLabel(""); onCreated(investigation);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not create the investigation.");
    } finally { setSaving(false); }
  }

  return (
    <Dialog open={open} onClose={onClose} width={500}>
      <form onSubmit={submit}>
        <div className="border-b border-[var(--border-card)] px-5 py-4"><h3 className="text-[16px] font-bold text-fg">New offline investigation</h3><p className="mt-1 text-[12px] text-muted">Create the case first, then upload evidence exports.</p></div>
        <div className="space-y-4 p-5">
          <label className="block"><span className="mb-1.5 block text-[12px] font-semibold text-secondary">Case name</span><Input autoFocus maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder="August suspicious sign-in review" /></label>
          <label className="block"><span className="mb-1.5 block text-[12px] font-semibold text-secondary">Tenant label</span><Input maxLength={120} value={tenantLabel} onChange={(event) => setTenantLabel(event.target.value)} placeholder="Customer or tenant name" /></label>
          {error && <p className="text-[12px] text-danger">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4"><Button type="button" onClick={onClose}>Cancel</Button><Button type="submit" variant="accent" disabled={saving || !name.trim() || !tenantLabel.trim()}>{saving ? <Loader2 className="animate-spin" /> : <Plus />}{saving ? "Creating…" : "Create case"}</Button></div>
      </form>
    </Dialog>
  );
}

function InvestigationWorkspace({ id }: { id: string }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [tab, setTab] = useState("overview");
  const [busy, setBusy] = useState<"upload" | "analyze" | "delete" | null>(null);
  const [actionError, setActionError] = useState("");
  const query = useRefreshingAsync(() => api.security.offlineInvestigation(id), [id], {
    cacheKey: `offline-investigations:${id}`,
    intervalMs: 5000,
  });
  const investigation = query.data;
  const canDelete = user?.permissions?.includes("security.manage") || user?.isAdmin;

  async function upload(files: File[]) {
    if (!files.length) return;
    setBusy("upload"); setActionError("");
    try {
      const oversized = files.find((file) => file.size > OFFLINE_EVIDENCE_MAX_FILE_BYTES);
      if (oversized) throw new Error(`${oversized.name} exceeds the 1 GiB per-file limit.`);
      // Large forensic exports are deliberately uploaded one at a time so a
      // multi-file selection does not multiply browser and API memory usage.
      for (const file of files) await api.security.uploadOfflineInvestigationFile(id, file);
      query.refresh();
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : "Evidence upload failed.");
    } finally { setBusy(null); }
  }

  async function analyze() {
    setBusy("analyze"); setActionError("");
    try { await api.security.analyzeOfflineInvestigation(id); query.refresh(); }
    catch (caught) { setActionError(caught instanceof Error ? caught.message : "Analysis could not start."); }
    finally { setBusy(null); }
  }

  async function remove() {
    if (!investigation || !window.confirm(`Delete “${investigation.name}” and all encrypted source evidence?`)) return;
    setBusy("delete"); setActionError("");
    try { await api.security.deleteOfflineInvestigation(id); navigate("/offline-investigations"); }
    catch (caught) { setActionError(caught instanceof Error ? caught.message : "Case deletion failed."); setBusy(null); }
  }

  if (query.loading && !investigation) return <CenteredState icon={<Loader2 className="animate-spin" />} label="Loading investigation…" />;
  if (query.error && !investigation) return <CenteredState icon={<AlertTriangle className="text-danger" />} label={query.error.message} />;
  if (!investigation) return null;

  const working = investigation.status === "queued" || investigation.status === "analyzing";
  return (
    <div className="space-y-4">
      <button className="inline-flex items-center gap-1.5 text-[12px] font-semibold text-muted hover:text-fg" onClick={() => navigate("/offline-investigations")}><ArrowLeft className="size-3.5" /> All investigations</button>
      <section className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2"><h2 className="truncate text-[21px] font-bold text-fg-strong">{investigation.name}</h2><CaseStatus status={investigation.status} progress={investigation.progress} /><Badge tone="info">Offline · read-only</Badge></div>
          <p className="mt-1 text-[12.5px] text-muted">{investigation.tenantLabel} · Created by {investigation.createdBy} · Updated {relativeTime(investigation.updatedAt)}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={query.refresh} disabled={query.refreshing}><RefreshCw className={cn(query.refreshing && "animate-spin")} /> Refresh</Button>
          {canDelete && <Button onClick={remove} disabled={busy !== null || working} className="text-danger"><Trash2 /> {busy === "delete" ? "Deleting…" : "Delete case"}</Button>}
        </div>
      </section>
      {actionError && <div className="rounded-[8px] border border-danger/20 bg-danger/5 px-3 py-2 text-[12.5px] text-danger">{actionError}</div>}
      {working && <AnalysisProgress investigation={investigation} />}
      {investigation.status !== "complete" ? <UploadWorkspace investigation={investigation} busy={busy} onUpload={upload} onAnalyze={analyze} /> : (
        <>
          <div className="overflow-hidden [&>div]:grid [&>div]:grid-cols-4 [&_button]:px-1 sm:[&_button]:px-3.5">
            <UnderlineTabs tabs={CASE_TABS} value={tab} onChange={setTab} />
          </div>
          {tab === "overview" && <AnalysisOverview investigation={investigation} onOpenDetections={() => setTab("detections")} />}
          {tab === "timeline" && <TimelinePanel timeline={investigation.timeline} />}
          {tab === "detections" && <DetectionPanel detections={investigation.detections} />}
          {tab === "evidence" && <EvidencePanel files={investigation.files} coverage={investigation.coverage} />}
        </>
      )}
    </div>
  );
}

function AnalysisProgress({ investigation }: { investigation: OfflineInvestigationDetail }) {
  return <div className="rounded-[10px] border border-info/20 bg-info/5 px-4 py-3"><div className="flex items-center justify-between text-[12px]"><span className="flex items-center gap-2 font-semibold text-info"><Loader2 className="size-4 animate-spin" /> {investigation.detail || "Analyzing evidence"}</span><span className="tabular text-secondary">{investigation.progress}%</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-control"><div className="h-full rounded-full bg-info transition-all" style={{ width: `${investigation.progress}%` }} /></div></div>;
}

function UploadWorkspace({ investigation, busy, onUpload, onAnalyze }: { investigation: OfflineInvestigationDetail; busy: string | null; onUpload: (files: File[]) => void; onAnalyze: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const working = investigation.status === "queued" || investigation.status === "analyzing";
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(300px,.8fr)]">
      <div className="space-y-4">
        <Card>
          <CardHeader><div><CardTitle>Upload evidence</CardTitle><p className="mt-0.5 text-[11.5px] text-muted">JSON, JSONL, or CSV · 1 GiB / 10 million records per file · 50 million records per case</p></div></CardHeader>
          <CardContent>
            <button type="button" disabled={working || busy !== null} onClick={() => inputRef.current?.click()} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); onUpload(Array.from(event.dataTransfer.files)); }} className={cn("grid min-h-44 w-full place-items-center rounded-[10px] border border-dashed bg-control/40 p-6 text-center transition-colors", dragging ? "border-info bg-info/5" : "border-[var(--border-strong)] hover:border-info/50", (working || busy) && "cursor-not-allowed opacity-60") }>
              <span><UploadCloud className="mx-auto size-8 text-info" /><span className="mt-3 block text-[13px] font-semibold text-fg">{busy === "upload" ? "Validating and encrypting…" : "Drop tenant evidence exports here"}</span><span className="mt-1 block text-[11.5px] text-muted">or choose one or more files</span></span>
            </button>
            <input ref={inputRef} className="hidden" type="file" accept=".json,.jsonl,.ndjson,.csv,application/json,text/csv" multiple onChange={(event) => { onUpload(Array.from(event.target.files ?? [])); event.currentTarget.value = ""; }} />
          </CardContent>
        </Card>
        <EvidenceFiles files={investigation.files} />
      </div>
      <div className="space-y-4">
        <Card>
          <CardHeader><CardTitle>Supported evidence</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <ManifestRow title="Microsoft Entra sign-ins" detail="Graph signIn exports with authentication requirement, methods, Conditional Access, IP, and location fields." />
            <ManifestRow title="Microsoft Entra directory audit" detail="Graph directoryAudit exports for identity, role, consent, and application changes." />
            <ManifestRow title="Microsoft 365 activity" detail="Unified audit JSON, expanded CSV, or native Microsoft Purview audit-search CSV with AuditData." />
          </CardContent>
        </Card>
        <Card className="border-[var(--ac)]/20">
          <CardContent>
            <div className="flex gap-3"><ShieldCheck className="mt-0.5 size-5 shrink-0 text-[var(--act)]" /><div><p className="text-[13px] font-semibold text-fg">Ready to reconstruct?</p><p className="mt-1 text-[11.5px] leading-5 text-muted">Analysis normalizes, deduplicates, detects, and correlates the uploaded records. Source evidence remains immutable and encrypted.</p></div></div>
            <Button className="mt-4 w-full" variant="accent" disabled={!investigation.files.length || busy !== null || working} onClick={onAnalyze}>{busy === "analyze" || working ? <Loader2 className="animate-spin" /> : <Play />}{working ? "Analysis running" : busy === "analyze" ? "Starting…" : "Analyze evidence"}</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function AnalysisOverview({ investigation, onOpenDetections }: { investigation: OfflineInvestigationDetail; onOpenDetections: () => void }) {
  const [selectedStoryline, setSelectedStoryline] = useState(investigation.storylines[0]?.id ?? "");
  const storyline = investigation.storylines.find((item) => item.id === selectedStoryline) ?? investigation.storylines[0];
  const availableEvidenceSources = investigation.coverage.filter((item) => item.status === "present" || item.status === "partial").length;
  const totalEvidenceSources = investigation.coverage.length;
  const evidenceCoverageTone: StatusTone = totalEvidenceSources === 0 ? "neutral" : availableEvidenceSources === totalEvidenceSources ? "success" : availableEvidenceSources > 0 ? "warning" : "neutral";
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-5">
        <Metric label="Normalized events" value={investigation.eventCount} icon={<CalendarClock />} />
        <Metric label="Detections" value={investigation.detectionCount} icon={<ShieldAlert />} tone={investigation.detectionCount ? "warning" : "neutral"} />
        <Metric label="High priority" value={investigation.highPriorityCount} icon={<CircleDot />} tone={investigation.highPriorityCount ? "danger" : "neutral"} />
        <Metric label="Storylines" value={investigation.storylineCount} icon={<FolderSearch />} tone={investigation.storylineCount ? "info" : "neutral"} />
        <Metric label="Evidence coverage" value={totalEvidenceSources ? `${availableEvidenceSources} / ${totalEvidenceSources}` : "—"} detail={totalEvidenceSources ? "source families available" : "awaiting analysis"} icon={<FileArchive />} tone={evidenceCoverageTone} />
      </div>
      <div className={cn("grid gap-4", storyline ? "xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,.75fr)]" : "grid-cols-1")}>
        <div className="space-y-4">
          <Card>
            <CardHeader><div><CardTitle>Attack storylines</CardTitle><p className="mt-0.5 text-[11.5px] text-muted">Correlated sequences from case evidence</p></div><span className="tabular text-[11.5px] text-muted">{investigation.storylines.length} found</span></CardHeader>
            {investigation.storylines.length ? investigation.storylines.map((item) => <StorylineRow key={item.id} storyline={item} active={item.id === storyline?.id} onClick={() => setSelectedStoryline(item.id)} />) : <CenteredState icon={<ShieldCheck className="text-success" />} label="No multi-signal storylines were found." />}
          </Card>
          <DetectionPanel detections={investigation.detections} compact onOpenAll={onOpenDetections} />
        </div>
        {storyline ? <div className="space-y-4"><StorylineInspector storyline={storyline} detections={investigation.detections} /></div> : null}
      </div>
    </div>
  );
}

function Metric({ label, value, detail, icon, tone = "neutral" }: { label: string; value: number | string; detail?: string; icon: React.ReactNode; tone?: StatusTone }) {
  const colors: Record<StatusTone, string> = { success: "text-success", danger: "text-danger", warning: "text-warning", info: "text-info", neutral: "text-faint" };
  return <Card><CardContent className="flex items-center justify-between p-3.5"><div><p className="text-[11.5px] text-muted">{label}</p><p className="mt-1 text-[22px] font-bold tabular text-fg">{typeof value === "number" ? value.toLocaleString() : value}</p>{detail ? <p className="mt-0.5 text-[10.5px] text-faint">{detail}</p> : null}</div><span className={cn("[&_svg]:size-5", colors[tone])}>{icon}</span></CardContent></Card>;
}

function StorylineRow({ storyline, active, onClick }: { storyline: SecurityStoryline; active: boolean; onClick: () => void }) {
  return <button onClick={onClick} className={cn("grid w-full gap-2 border-b border-[var(--border-card)] px-4 py-3 text-left last:border-0 hover:bg-[var(--row-hover)] sm:grid-cols-[90px_minmax(0,1fr)_76px] sm:items-center", active && "bg-[var(--acb)]")}><span><SeverityBadge severity={storyline.severity} /></span><span className="min-w-0"><span className="block truncate text-[12.5px] font-semibold text-fg">{storyline.title}</span><span className="mt-0.5 block truncate text-[11.5px] text-muted">{storyline.signalCount} signals · {storyline.stages.join(" → ")}</span></span><span className="text-right text-[11.5px] tabular text-secondary">Risk {storyline.riskScore}</span></button>;
}

function StorylineInspector({ storyline, detections }: { storyline: SecurityStoryline; detections: SecurityNativeDetection[] }) {
  const contributingDetections = useMemo(() => contributingStorylineDetections(storyline, detections), [storyline, detections]);
  const identity = primaryStorylineEntity(storyline);
  const visibleDetections = contributingDetections.slice(0, 6);
  return (
    <Card className="overflow-hidden">
      <CardHeader><div><CardTitle>Selected storyline</CardTitle><p className="mt-0.5 text-[10.5px] text-muted">RTM correlation hypothesis · analyst validation required</p></div><SeverityBadge severity={storyline.severity} /></CardHeader>
      <CardContent className="space-y-5">
        <section>
          <h3 className="text-[15px] font-semibold leading-5 text-fg">{storyline.title}</h3>
          <p className="mt-2 text-[12px] leading-5 text-secondary">{storyline.summary}</p>
          <div className="mt-3 rounded-[9px] border border-info/20 bg-info/5 px-3 py-2.5">
            <p className="text-[10.5px] font-bold uppercase tracking-[.07em] text-info">What RTM observed</p>
            <p className="mt-1.5 text-[11.5px] leading-5 text-secondary">{storylineNarrative(storyline, contributingDetections)}</p>
          </div>
        </section>

        <section>
          <StorylineSectionTitle>Assessment</StorylineSectionTitle>
          <div className="mt-2 grid grid-cols-2 gap-2">
            <StorylineFact label="Risk score" value={`${storyline.riskScore} / 100`} detail={`${storyline.severity} severity`} />
            <StorylineFact label="Confidence" value={storyline.confidence} detail="Evidence strength" capitalize />
            <StorylineFact label="Evidence window" value={storylineDuration(storyline.firstSeen, storyline.lastSeen)} detail={`${formatDateTime(storyline.firstSeen)} – ${formatDateTime(storyline.lastSeen)}`} />
            <StorylineFact label="Connected signals" value={storyline.signalCount.toLocaleString()} detail={`${new Set(contributingDetections.map((item) => item.ruleId)).size || storyline.detectionIds.length} detection types`} />
          </div>
        </section>

        <section>
          <StorylineSectionTitle>Attack progression</StorylineSectionTitle>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {storyline.stages.map((stage, index) => <span key={stage} className="inline-flex items-center gap-1.5 rounded-[6px] border border-[var(--border-card)] bg-control px-2 py-1 text-[10.5px] font-semibold text-secondary">{index > 0 ? <ArrowRight className="size-3 text-faint" /> : null}{stage}</span>)}
          </div>
        </section>

        <section>
          <StorylineSectionTitle>Affected scope</StorylineSectionTitle>
          <dl className="mt-2 space-y-2 text-[11.5px]">
            <StorylineScopeRow label="Primary identity" value={identity ? `${identity.type}: ${identity.label}` : "Not identified in supplied evidence"} />
            <StorylineScopeRow label="Workloads" value={storyline.workloads.length ? storyline.workloads.join(" · ") : "Not identified"} />
            <StorylineScopeRow label="Impact" value={`${storyline.affectedUsers} ${storyline.affectedUsers === 1 ? "account" : "accounts"} · ${storyline.affectedResources} ${storyline.affectedResources === 1 ? "resource" : "resources"}`} />
          </dl>
          {storyline.entities.length ? <div className="mt-2 flex flex-wrap gap-1.5">{storyline.entities.slice(0, 8).map((entity) => <Badge key={entity.key} tone={entity.primary ? "danger" : "neutral"} dot={false}>{entity.type}: {entity.label}</Badge>)}{storyline.entities.length > 8 ? <Badge tone="neutral" dot={false}>+{storyline.entities.length - 8} more</Badge> : null}</div> : null}
        </section>

        <section>
          <StorylineSectionTitle>Evidence highlights</StorylineSectionTitle>
          {visibleDetections.length ? <div className="relative mt-3 space-y-3 before:absolute before:bottom-2 before:left-[5px] before:top-2 before:w-px before:bg-[var(--border-strong)]">{visibleDetections.map((detection) => (
            <article key={detection.id} className="relative pl-5">
              <span className={cn("absolute left-0 top-1.5 size-[11px] rounded-full border-2 border-card", detection.severity === "Critical" || detection.severity === "High" ? "bg-danger" : detection.severity === "Medium" ? "bg-warning" : "bg-info")} />
              <div>
                <div className="flex flex-wrap items-center gap-1.5"><span className="text-[11.5px] font-semibold leading-4 text-fg">{detection.title}</span><span className="text-[10px] capitalize text-faint">{detection.confidence} confidence</span></div>
                <p className="mt-0.5 text-[10.5px] leading-4 text-muted">{detection.description}</p>
                <p className="mt-1 flex flex-wrap items-center gap-x-2 text-[10px] text-faint"><span className="inline-flex items-center gap-1"><Clock3 className="size-3" />{formatDateTime(detection.occurredAt)}</span><span className="mono">{detection.ruleId}</span></p>
              </div>
            </article>
          ))}</div> : <p className="mt-2 text-[11.5px] leading-4 text-muted">The storyline references detections outside the returned case window. Open Case detections for the retained rule results.</p>}
          {contributingDetections.length > visibleDetections.length ? <p className="mt-2 text-[10.5px] text-muted">{contributingDetections.length - visibleDetections.length} more contributing detections are available in Case detections.</p> : null}
        </section>

        <section>
          <StorylineSectionTitle>Why RTM connected this</StorylineSectionTitle>
          <ul className="mt-2 space-y-2">{storyline.reasons.map((reason) => <li key={reason} className="flex gap-2 text-[11.5px] leading-4.5 text-secondary"><GitBranch className="mt-0.5 size-3.5 shrink-0 text-info" />{reason}</li>)}</ul>
        </section>

        {(storyline.weakEvidence?.length ?? 0) > 0 ? <section><StorylineSectionTitle>Evidence gaps</StorylineSectionTitle><div className="mt-2 rounded-[8px] border border-warning/25 bg-warning/5 px-3 py-2.5"><ul className="space-y-1.5">{storyline.weakEvidence?.map((item) => <li key={item} className="flex gap-2 text-[11px] leading-4 text-secondary"><AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" />{item}</li>)}</ul></div></section> : null}

        <section>
          <StorylineSectionTitle>Recommended investigation</StorylineSectionTitle>
          <ol className="mt-2 space-y-2">{storyline.recommendedActions.map((action, index) => <li key={action} className="flex gap-2.5 text-[11.5px] leading-4.5 text-secondary"><span className="grid size-5 shrink-0 place-items-center rounded-full bg-danger/10 text-[10px] font-bold text-danger">{index + 1}</span>{action}</li>)}</ol>
          <p className="mt-3 flex gap-2 border-t border-[var(--border-card)] pt-3 text-[10.5px] leading-4 text-muted"><ListChecks className="mt-0.5 size-3.5 shrink-0" />Guidance only. This offline case is read-only; validate the source evidence before acting in the tenant.</p>
        </section>
      </CardContent>
    </Card>
  );
}

function StorylineSectionTitle({ children }: { children: React.ReactNode }) {
  return <h4 className="text-[10.5px] font-bold uppercase tracking-[.08em] text-faint">{children}</h4>;
}

function StorylineFact({ label, value, detail, capitalize = false }: { label: string; value: string; detail: string; capitalize?: boolean }) {
  return <div className="rounded-[8px] border border-[var(--border-card)] bg-control/30 px-2.5 py-2"><p className="text-[9.5px] font-bold uppercase tracking-[.06em] text-faint">{label}</p><p className={cn("mt-1 text-[13px] font-bold text-fg", capitalize && "capitalize")}>{value}</p><p className="mt-0.5 text-[9.5px] leading-3.5 text-muted">{detail}</p></div>;
}

function StorylineScopeRow({ label, value }: { label: string; value: string }) {
  return <div className="grid gap-0.5 sm:grid-cols-[100px_minmax(0,1fr)]"><dt className="text-faint">{label}</dt><dd className="break-words text-secondary sm:text-right">{value}</dd></div>;
}

function TimelinePanel({ timeline }: { timeline: OfflineTimelineEvent[] }) {
  const [query, setQuery] = useState("");
  const [focus, setFocus] = useState<TimelineFocus>("all");
  const [workload, setWorkload] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const workloads = useMemo(() => timelineWorkloads(timeline), [timeline]);
  const filteredEvents = useMemo(() => filterTimelineEvents(timeline, { query, focus, workload }), [timeline, query, focus, workload]);
  const groups = useMemo(() => groupTimelineEvents(filteredEvents), [filteredEvents]);
  const actors = useMemo(() => new Set(filteredEvents.map((event) => event.actor).filter(Boolean)).size, [filteredEvents]);
  const clientIPs = useMemo(() => new Set(filteredEvents.map((event) => event.clientIp).filter(Boolean)).size, [filteredEvents]);
  const signalRules = useMemo(() => new Set(filteredEvents.flatMap((event) => (event.signals ?? []).map((signal) => signal.ruleId))).size, [filteredEvents]);
  return (
    <Card className="overflow-hidden">
      <CardHeader><div><CardTitle>Investigation activity</CardTitle><p className="mt-0.5 text-[11.5px] text-muted">Similar records within 15 minutes are grouped into useful activity bursts</p></div><span className="tabular text-[11.5px] text-muted">{filteredEvents.length.toLocaleString()} records · {groups.length.toLocaleString()} bursts</span></CardHeader>
      <div className="grid gap-2 border-b border-[var(--border-card)] p-4 lg:grid-cols-[minmax(260px,1fr)_170px_180px]">
        <SearchInput value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search actor, target, IP, operation, application, or signal…" />
        <select aria-label="Investigation focus" className={TIMELINE_SELECT_CLASS} value={focus} onChange={(event) => setFocus(event.target.value as TimelineFocus)}><option value="all">All activity</option><option value="signals">Detection matches</option><option value="failures">Failed activity</option><option value="external">External access</option></select>
        <select aria-label="Workload" className={TIMELINE_SELECT_CLASS} value={workload} onChange={(event) => setWorkload(event.target.value)}><option value="">All workloads</option>{workloads.map((item) => <option key={item}>{item}</option>)}</select>
      </div>
      <div className="grid grid-cols-2 border-b border-[var(--border-card)] bg-control/20 sm:grid-cols-4">
        <TimelineStat label="Activity bursts" value={groups.length} />
        <TimelineStat label="Actors" value={actors} />
        <TimelineStat label="Client IPs" value={clientIPs} />
        <TimelineStat label="Matched rules" value={signalRules} />
      </div>
      <div>{groups.length ? groups.map((group) => <TimelineActivityRow key={group.id} group={group} expanded={expanded === group.id} onToggle={() => setExpanded((current) => current === group.id ? null : group.id)} />) : <CenteredState icon={<CalendarClock />} label={timeline.length ? "No activity matches these filters." : "No normalized events available."} />}</div>
    </Card>
  );
}

function TimelineStat({ label, value }: { label: string; value: number }) {
  return <div className="border-r border-[var(--border-card)] px-4 py-2.5 last:border-r-0"><p className="text-[10.5px] text-faint">{label}</p><p className="mt-0.5 text-[15px] font-bold tabular text-fg">{value.toLocaleString()}</p></div>;
}

function TimelineActivityRow({ group, expanded, onToggle }: { group: TimelineActivityGroup; expanded: boolean; onToggle: () => void }) {
  const factPreview = group.facts.slice(0, 4);
  return (
    <div className="border-b border-[var(--border-card)] last:border-0">
      <button type="button" aria-expanded={expanded} onClick={onToggle} className="grid w-full gap-3 px-4 py-3 text-left hover:bg-[var(--row-hover)] md:grid-cols-[130px_minmax(0,1fr)_170px_20px] md:items-start">
        <span><span className="block text-[11.5px] font-semibold tabular text-secondary">{formatActivityDate(group.newestAt)}</span><span className="mt-0.5 block text-[10.5px] tabular text-faint">{formatActivityTimeRange(group.oldestAt, group.newestAt)}</span></span>
        <span className="min-w-0"><span className="flex flex-wrap items-center gap-2"><span className="text-[13px] font-semibold text-fg">{group.operation}</span>{group.events.length > 1 ? <Badge tone="neutral" dot={false}>{group.events.length} events</Badge> : null}{group.severity ? <SeverityBadge severity={group.severity} /> : null}</span><span className="mt-1 flex min-w-0 items-center gap-1 text-[11.5px] text-muted"><span className="truncate">{group.actor || "Unknown actor"}</span>{group.objectId && group.objectId !== group.actor ? <><ChevronRight className="size-3 shrink-0" /><span className="truncate text-secondary">{group.objectId}</span></> : null}</span>{factPreview.length ? <span className="mt-2 flex flex-wrap gap-1.5">{factPreview.map((fact) => <span key={`${fact.label}:${fact.value}`} className="rounded-[5px] bg-control px-1.5 py-0.5 text-[10.5px] text-secondary"><span className="text-faint">{fact.label}:</span> {fact.value}</span>)}</span> : null}{group.signals.length ? <span className="mt-2 block text-[11px] font-semibold text-warning">{group.signals.length} detection {group.signals.length === 1 ? "match" : "matches"}</span> : null}</span>
        <span className="md:text-right"><span className="block mono text-[11px] text-secondary">{group.clientIp || "No client IP"}</span><span className={cn("mt-1 block text-[11px]", resultTone(group.resultStatus))}>{group.resultStatus || "Result not supplied"}</span><span className="mt-1 block text-[10.5px] text-faint">{group.workload} · {evidenceLabel(group.evidenceType)}</span></span>
        <ChevronRight className={cn("mt-0.5 size-4 text-faint transition-transform", expanded && "rotate-90")} />
      </button>
      {expanded ? <TimelineActivityDetails group={group} /> : null}
    </div>
  );
}

function TimelineActivityDetails({ group }: { group: TimelineActivityGroup }) {
  return <div className="grid gap-4 border-t border-[var(--border-card)] bg-control/20 px-4 py-3 lg:grid-cols-[minmax(0,1fr)_minmax(260px,.7fr)]"><div><p className="text-[10.5px] font-bold uppercase tracking-[.07em] text-faint">Detection context</p>{group.signals.length ? <div className="mt-2 space-y-2">{group.signals.map((signal) => <div key={`${signal.ruleId}:${signal.title}`} className="flex flex-wrap items-center gap-2"><SeverityBadge severity={signal.severity} /><span className="text-[11.5px] font-semibold text-fg">{signal.title}</span><span className="mono text-[10.5px] text-faint">{signal.ruleId}</span></div>)}</div> : <p className="mt-2 text-[11.5px] text-muted">No detection rule matched this activity burst.</p>}</div><div><p className="text-[10.5px] font-bold uppercase tracking-[.07em] text-faint">Evidence context</p><dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">{group.facts.map((fact) => <div key={`${fact.label}:${fact.value}`}><dt className="text-[10px] text-faint">{fact.label}</dt><dd className="mt-0.5 break-words text-[11.5px] text-secondary">{fact.value}</dd></div>)}<div><dt className="text-[10px] text-faint">Provider records</dt><dd className="mt-0.5 text-[11.5px] text-secondary">{group.events.length.toLocaleString()}</dd></div><div><dt className="text-[10px] text-faint">Source</dt><dd className="mt-0.5 text-[11.5px] text-secondary">{group.source}</dd></div></dl></div></div>;
}

function DetectionPanel({ detections, compact = false, onOpenAll }: { detections: SecurityNativeDetection[]; compact?: boolean; onOpenAll?: () => void }) {
  const visibleDetections = compact ? detections.slice(0, 8) : detections;
  const resultLabel = compact && detections.length > visibleDetections.length ? `${visibleDetections.length} of ${detections.length} shown` : `${detections.length} results`;
  return <Card><CardHeader><CardTitle>Case detections</CardTitle><span className="tabular text-[11.5px] text-muted">{resultLabel}</span></CardHeader>{visibleDetections.length ? visibleDetections.map((detection) => <div key={detection.id} className="grid gap-2 border-b border-[var(--border-card)] px-4 py-3 last:border-0 md:grid-cols-[90px_minmax(0,1fr)_140px_90px]"><span><SeverityBadge severity={detection.severity} /></span><span><span className="block text-[12.5px] font-semibold text-fg">{detection.title}</span><span className="mt-0.5 block text-[11.5px] leading-4 text-muted">{detection.description}</span></span><span className="mono text-[11px] text-secondary">{detection.ruleId}</span><span className="text-[11.5px] text-muted md:text-right">{formatDateTime(detection.occurredAt)}</span></div>) : <CenteredState icon={<ShieldCheck className="text-success" />} label="No detection rules matched." />}{compact && visibleDetections.length > 0 && <button type="button" onClick={onOpenAll} className="flex w-full items-center justify-between px-4 py-2.5 text-left text-[11.5px] font-semibold text-info hover:bg-[var(--row-hover)]"><span>View all case detections</span><ChevronRight className="size-3.5" /></button>}</Card>;
}

function EvidencePanel({ files, coverage }: { files: OfflineInvestigationFile[]; coverage: OfflineEvidenceCoverage[] }) {
  return <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(320px,.7fr)]"><EvidenceFiles files={files} /><CoveragePanel coverage={coverage} /></div>;
}

function EvidenceFiles({ files }: { files: OfflineInvestigationFile[] }) {
  return <Card><CardHeader><CardTitle>Source files</CardTitle><span className="tabular text-[11.5px] text-muted">{files.length} files</span></CardHeader>{files.length ? files.map((file) => <div key={file.id} className="grid gap-2 border-b border-[var(--border-card)] px-4 py-3 last:border-0 sm:grid-cols-[minmax(0,1fr)_130px_90px] sm:items-center"><span className="flex min-w-0 items-center gap-2.5"><FileJson className="size-4 shrink-0 text-info" /><span className="min-w-0"><span className="block truncate text-[12.5px] font-semibold text-fg">{file.name}</span><span className="mono block truncate text-[10.5px] text-faint">SHA-256 {file.sha256.slice(0, 16)}…</span></span></span><span className="text-[11.5px] text-secondary">{evidenceLabel(file.evidenceType)}</span><span className="text-[11.5px] tabular text-muted sm:text-right">{file.recordCount.toLocaleString()} records<br />{formatBytes(file.sizeBytes)}</span></div>) : <CenteredState icon={<FileArchive />} label="No evidence files uploaded." />}</Card>;
}

function CoveragePanel({ coverage }: { coverage: OfflineEvidenceCoverage[] }) {
  return <Card><CardHeader><CardTitle>Evidence coverage</CardTitle></CardHeader><CardContent className="space-y-3">{coverage.length ? coverage.map((item) => <div key={item.key} className="rounded-[8px] border border-[var(--border-card)] bg-control/30 p-3"><div className="flex items-center justify-between gap-2"><span className="text-[12px] font-semibold text-fg">{item.label}</span><CoverageBadge status={item.status} /></div><p className="mt-1 text-[11px] leading-4 text-muted">{item.records.toLocaleString()} records · {item.detail}</p>{item.missingFields?.length ? <p className="mt-1.5 text-[10.5px] text-warning">Missing: {item.missingFields.join(", ")}</p> : null}</div>) : <p className="text-[11.5px] text-muted">Coverage is calculated when analysis completes.</p>}</CardContent></Card>;
}

function ManifestRow({ title, detail }: { title: string; detail: string }) {
  return <div className="flex gap-2.5"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" /><div><p className="text-[12px] font-semibold text-fg">{title}</p><p className="mt-0.5 text-[11px] leading-4 text-muted">{detail}</p></div></div>;
}

function CenteredState({ icon, label }: { icon: React.ReactNode; label: string }) {
  return <div className="grid min-h-40 place-items-center p-6 text-center"><div className="[&_svg]:mx-auto [&_svg]:mb-2 [&_svg]:size-5 [&_svg]:text-faint"><span>{icon}</span><p className="text-[12.5px] text-muted">{label}</p></div></div>;
}

function CaseStatus({ status, progress }: Pick<OfflineInvestigation, "status" | "progress">) {
  const map: Record<string, { label: string; tone: StatusTone }> = { draft: { label: "Draft", tone: "neutral" }, ready: { label: "Ready", tone: "info" }, queued: { label: `Queued ${progress}%`, tone: "neutral" }, analyzing: { label: `Analyzing ${progress}%`, tone: "info" }, complete: { label: "Complete", tone: "success" }, failed: { label: "Failed", tone: "danger" } };
  const item = map[status] ?? { label: status, tone: "neutral" as StatusTone };
  return <Badge tone={item.tone}>{item.label}</Badge>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const tone: StatusTone = severity === "Critical" || severity === "High" ? "danger" : severity === "Medium" ? "warning" : severity === "Low" ? "info" : "neutral";
  return <Badge tone={tone}>{severity}</Badge>;
}

function CoverageBadge({ status }: { status: OfflineEvidenceCoverage["status"] }) {
  return <Badge tone={status === "present" ? "success" : status === "partial" ? "warning" : "neutral"}>{status === "present" ? "Present" : status === "partial" ? "Partial" : "Missing"}</Badge>;
}

function evidenceLabel(value: string) {
  return ({ entra_sign_ins: "Entra sign-ins", entra_directory_audits: "Directory audit", m365_activity: "M365 activity" } as Record<string, string>)[value] ?? value;
}

function formatDateTime(value?: string) { return value ? new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value)) : "—"; }
function formatActivityDate(value: string) { return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(new Date(value)); }
function formatActivityTimeRange(oldest: string, newest: string) {
  const formatter = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
  return oldest === newest ? formatter.format(new Date(newest)) : `${formatter.format(new Date(oldest))}–${formatter.format(new Date(newest))}`;
}
function resultTone(value?: string) {
  if (!value) return "text-faint";
  return ["success", "succeeded", "0"].includes(value.toLocaleLowerCase()) ? "text-success" : "text-danger";
}
function formatBytes(value: number) { return value >= 1_048_576 ? `${(value / 1_048_576).toFixed(1)} MiB` : `${Math.max(1, Math.round(value / 1024))} KiB`; }
function relativeTime(value: string) { const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000)); return minutes < 1 ? "just now" : minutes < 60 ? `${minutes}m ago` : minutes < 1440 ? `${Math.round(minutes / 60)}h ago` : `${Math.round(minutes / 1440)}d ago`; }
