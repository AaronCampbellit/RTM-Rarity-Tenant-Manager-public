import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, Home, RotateCcw } from "lucide-react";

interface Props { children: ReactNode }
interface State { error?: Error }

/** Contains a route/render failure so one broken drawer cannot blank RTM. */
export class RouteErrorBoundary extends Component<Props, State> {
  state: State = {};

  static getDerivedStateFromError(error: Error): State { return { error }; }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("RTM route render failed", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <section role="alert" className="mx-auto mt-12 max-w-xl rounded-[12px] border border-danger/25 bg-card p-6 text-center shadow-[var(--shadow-card)]">
        <AlertTriangle className="mx-auto size-7 text-danger" />
        <h2 className="mt-3 text-[17px] font-bold text-fg-strong">This workspace could not be displayed</h2>
        <p className="mt-2 text-[12px] leading-5 text-muted">RTM contained the error so the rest of the console remains available. Retry the page or return to the dashboard.</p>
        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <button type="button" className="inline-flex h-9 items-center gap-2 rounded-[8px] border border-[var(--border-strong)] bg-control px-4 text-[12px] font-semibold text-fg" onClick={() => window.location.reload()}><RotateCcw className="size-4" />Retry page</button>
          <a href="/dashboard" className="inline-flex h-9 items-center gap-2 rounded-[8px] bg-accent px-4 text-[12px] font-semibold text-white"><Home className="size-4" />Dashboard</a>
        </div>
      </section>
    );
  }
}
