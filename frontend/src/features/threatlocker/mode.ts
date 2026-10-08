import type { Device, StatusTone } from "@/types";

/** Display label for a device protection mode. */
export function deviceModeLabel(mode: Device["mode"]): string {
  switch (mode) {
    case "secured":
      return "Secured";
    case "monitor_only":
      return "Monitor Only";
    case "learning":
      return "Learning";
    case "installation":
      return "Installation";
    case "maintenance":
      return "Maintenance";
    case "lockdown":
      return "Lockdown";
    case "isolated":
      return "Isolated";
  }
}

/** Badge tone: secured is good, reduced protection warns, protection-off is
 * danger, containment states (lockdown/isolation) are informational. */
export function deviceModeTone(mode: Device["mode"]): StatusTone {
  switch (mode) {
    case "secured":
      return "success";
    case "maintenance":
      return "danger";
    case "lockdown":
    case "isolated":
      return "info";
    default:
      return "warning";
  }
}
