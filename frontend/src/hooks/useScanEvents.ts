import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ProgressEvent } from "../types";

/**
 * Subscribe to a scan's Server-Sent Events stream.
 * EventSource reconnects on its own; we close it once the scan reaches a final state.
 */
export function useScanEvents(scanId: string | null, enabled: boolean) {
  const [event, setEvent] = useState<ProgressEvent | null>(null);

  useEffect(() => {
    if (!scanId || !enabled) return;
    setEvent(null);
    const source = new EventSource(api.eventsUrl(scanId));
    source.onmessage = (msg) => {
      const data = JSON.parse(msg.data) as ProgressEvent;
      setEvent(data);
      if (data.status === "completed" || data.status === "failed") source.close();
    };
    return () => source.close();
  }, [scanId, enabled]);

  return event;
}
