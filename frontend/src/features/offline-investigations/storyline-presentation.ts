import type { SecurityNativeDetection, SecurityStoryline, SecurityStorylineEntity } from "@/types";

export function contributingStorylineDetections(
  storyline: SecurityStoryline,
  detections: SecurityNativeDetection[],
): SecurityNativeDetection[] {
  const ids = new Set(storyline.detectionIds ?? []);
  return detections
    .filter((detection) => ids.has(detection.id))
    .sort((left, right) => Date.parse(left.occurredAt) - Date.parse(right.occurredAt));
}

export function primaryStorylineEntity(storyline: SecurityStoryline): SecurityStorylineEntity | undefined {
  return storyline.entities.find((entity) => entity.primary)
    ?? storyline.entities.find((entity) => entity.type.toLocaleLowerCase() === "account")
    ?? storyline.entities[0];
}

export function storylineDuration(firstSeen: string, lastSeen: string): string {
  const milliseconds = Math.max(0, Date.parse(lastSeen) - Date.parse(firstSeen));
  const totalMinutes = Math.floor(milliseconds / 60_000);
  if (totalMinutes < 1) return "Less than 1 minute";
  const days = Math.floor(totalMinutes / 1_440);
  const hours = Math.floor((totalMinutes % 1_440) / 60);
  const minutes = totalMinutes % 60;
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", minutes ? `${minutes}m` : ""].filter(Boolean).join(" ");
}

export function storylineNarrative(storyline: SecurityStoryline, detections: SecurityNativeDetection[]): string {
  const identity = primaryStorylineEntity(storyline)?.label ?? "the same identity or resource";
  const signalCount = detections.length || storyline.signalCount;
  const scope = storyline.workloads.length
    ? ` across ${storyline.workloads.join(", ")}`
    : "";
  if (detections.length >= 2) {
    return `RTM connected ${signalCount} detections involving ${identity}${scope}. The sequence begins with “${detections[0].title}” and later includes “${detections.at(-1)?.title},” which together match this storyline pattern.`;
  }
  return `RTM connected ${signalCount} supporting ${signalCount === 1 ? "detection" : "detections"} involving ${identity}${scope}. The correlation matches this storyline pattern and should be validated against the source evidence.`;
}
