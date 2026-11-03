import { useCallback, useEffect, useRef, useState } from "react";

export function useTask() {
  const epoch = useRef(0);
  const locked = useRef(false);
  const [busy, setBusy] = useState(false);
  useEffect(
    () => () => {
      epoch.current++;
      locked.current = false;
    },
    [],
  );
  const cancel = useCallback(() => {
    epoch.current++;
    locked.current = false;
    setBusy(false);
  }, []);
  const run = useCallback(
    async (
      job: (current: () => boolean) => Promise<void>,
      failed: (error: unknown) => void,
    ) => {
      if (locked.current) return;
      locked.current = true;
      setBusy(true);
      const version = epoch.current,
        current = () => version === epoch.current;
      try {
        await job(current);
      } catch (error) {
        if (current()) failed(error);
      } finally {
        if (current()) {
          locked.current = false;
          setBusy(false);
        }
      }
    },
    [],
  );
  return { busy, run, cancel };
}
export const errorMessage = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";
