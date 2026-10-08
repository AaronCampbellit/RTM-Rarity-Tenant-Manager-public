import { Circle, Route, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { SecurityRemediationPlan, StatusTone } from "@/types";

export function IncidentRemediationPlan({ plan }: { plan: SecurityRemediationPlan }) {
  return (
    <section aria-labelledby="incident-remediation-heading">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3
          id="incident-remediation-heading"
          className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint"
        >
          Recommended response
        </h3>
        <Badge tone="info">{plan.category}</Badge>
      </div>

      <div className="overflow-hidden rounded-[10px] border border-info/25 bg-card">
        <div className="flex gap-3 border-b border-[var(--border-card)] bg-info/5 px-3.5 py-3">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-info" />
          <div>
            <p className="text-[12.5px] font-semibold text-fg">Analyst-guided remediation</p>
            <p className="mt-1 text-[11.5px] leading-4 text-secondary">{plan.summary}</p>
            <p className="mt-1.5 text-[10.5px] leading-4 text-muted">
              Guidance only. Verify the evidence first; tenant changes still require RTM What-If approval.
            </p>
          </div>
        </div>

        <ol className="divide-y divide-[var(--border-card)]">
          {plan.steps.map((step, index) => (
            <li key={`${step.phase}-${step.title}`} className="flex gap-3 px-3.5 py-3">
              <span className="grid size-6 shrink-0 place-items-center rounded-full bg-raised text-[11px] font-bold text-secondary">
                {index + 1}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge tone={remediationUrgencyTone(step.urgency)}>{step.urgency}</Badge>
                  <span className="text-[10px] font-bold uppercase tracking-[.4px] text-faint">
                    {step.phase}
                  </span>
                </div>
                <p className="mt-1.5 text-[12.5px] font-semibold text-fg">{step.title}</p>
                <p className="mt-1 text-[11.5px] leading-[17px] text-secondary">{step.description}</p>
                {step.rtmAction && (
                  <p className="mt-2 inline-flex items-start gap-1.5 rounded-[6px] bg-raised px-2 py-1.5 text-[10.5px] font-medium leading-4 text-body">
                    <Route className="mt-0.5 size-3 shrink-0 text-info" />
                    <span><span className="text-muted">In RTM:</span> {step.rtmAction}</span>
                  </p>
                )}
              </div>
            </li>
          ))}
        </ol>

        <details className="border-t border-[var(--border-card)]">
          <summary className="cursor-pointer px-3.5 py-3 text-[11.5px] font-semibold text-secondary hover:text-fg">
            Resolution checklist · {plan.completionCriteria.length} checks
          </summary>
          <ul className="space-y-2 border-t border-[var(--border-card)] px-3.5 py-3">
            {plan.completionCriteria.map((criterion) => (
              <li key={criterion} className="flex items-start gap-2 text-[11.5px] leading-4 text-secondary">
                <Circle className="mt-0.5 size-3.5 shrink-0 text-faint" />
                <span>{criterion}</span>
              </li>
            ))}
          </ul>
        </details>
      </div>
    </section>
  );
}

export function remediationUrgencyTone(urgency: string): StatusTone {
  if (urgency === "Immediate") return "danger";
  if (urgency === "High") return "warning";
  return "neutral";
}
