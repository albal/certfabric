import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

import { parseAnsi } from "../ansi";

type Job = { id: string; title: string };
type End = { state: string; error: string | null };

const TerminalContext = createContext<(jobId: string, title: string) => void>(() => {});

/** Open the slide-out terminal on a running job: `useTerminal()(jobId, title)`. */
export const useTerminal = () => useContext(TerminalContext);

function useJobStream(jobId: string | null) {
  const [lines, setLines] = useState<string[]>([]);
  const [end, setEnd] = useState<End | null>(null);
  const queryClient = useQueryClient();
  useEffect(() => {
    if (!jobId) return;
    setLines([]);
    setEnd(null);
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${scheme}://${window.location.host}/ws/jobs/${jobId}`);
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "line") setLines((previous) => [...previous, message.text]);
      else if (message.type === "end") {
        setEnd({ state: message.state, error: message.error });
        void queryClient.invalidateQueries();
      } else if (message.type === "error") setEnd({ state: "failed", error: message.message });
    };
    socket.onerror = () => setEnd((previous) => previous ?? { state: "failed", error: "Connection to the log stream failed" });
    return () => socket.close();
  }, [jobId, queryClient]);
  return { lines, end };
}

export function TerminalProvider({ children }: { children: ReactNode }) {
  const [job, setJob] = useState<Job | null>(null);
  const open = useCallback((id: string, title: string) => setJob({ id, title }), []);
  const { lines, end } = useJobStream(job?.id ?? null);
  const bottom = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "end" });
  }, [lines, end]);

  return (
    <TerminalContext.Provider value={open}>
      {children}
      <aside
        aria-label="Deployment terminal"
        data-testid="terminal"
        aria-hidden={!job}
        className={`fixed inset-y-0 right-0 z-20 flex w-full max-w-2xl flex-col border-l border-black bg-slate-950 text-slate-100 shadow-2xl transition-transform ${
          job ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <header className="flex items-center justify-between border-b border-slate-700 bg-slate-900 px-4 py-3">
          <div>
            <div className="text-sm font-semibold">{job?.title}</div>
            <div data-testid="terminal-status" className="text-xs">
              {!end && <span className="text-blue-400">Running…</span>}
              {end?.state === "succeeded" && <span className="text-green-400">Succeeded</span>}
              {end?.state === "failed" && <span className="text-red-400">Failed: {end.error}</span>}
            </div>
          </div>
          <button onClick={() => setJob(null)} className="rounded border border-slate-600 px-3 py-1 text-sm hover:bg-slate-800">
            Close
          </button>
        </header>
        <pre data-testid="terminal-output" className="flex-1 overflow-auto p-4 font-mono text-xs leading-relaxed">
          {lines.map((line, i) => (
            <div key={i}>
              {parseAnsi(line).map((segment, j) => (
                <span key={j} className={segment.className || undefined}>
                  {segment.text}
                </span>
              ))}
            </div>
          ))}
          <div ref={bottom} />
        </pre>
      </aside>
    </TerminalContext.Provider>
  );
}
