// Minimal ANSI SGR parser for the terminal drawer: colours, bold and reset.

export type Segment = { text: string; className: string };

const COLOURS: Record<number, string> = {
  30: "text-slate-500", 31: "text-red-400", 32: "text-green-400", 33: "text-yellow-300",
  34: "text-blue-400", 35: "text-fuchsia-400", 36: "text-cyan-300", 37: "text-slate-100",
  90: "text-slate-400", 91: "text-red-300", 92: "text-green-300", 93: "text-yellow-200",
  94: "text-blue-300", 95: "text-fuchsia-300", 96: "text-cyan-200", 97: "text-white",
};

export function parseAnsi(line: string): Segment[] {
  const segments: Segment[] = [];
  let colour = "";
  let bold = false;
  // eslint-disable-next-line no-control-regex
  const pattern = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  for (const match of line.matchAll(pattern)) {
    if (match.index! > last) segments.push({ text: line.slice(last, match.index), className: `${colour} ${bold ? "font-bold" : ""}`.trim() });
    for (const code of (match[1] || "0").split(";").map(Number)) {
      if (code === 0) [colour, bold] = ["", false];
      else if (code === 1) bold = true;
      else if (code === 22) bold = false;
      else if (code === 39) colour = "";
      else if (COLOURS[code]) colour = COLOURS[code];
    }
    last = match.index! + match[0].length;
  }
  if (last < line.length) segments.push({ text: line.slice(last), className: `${colour} ${bold ? "font-bold" : ""}`.trim() });
  return segments;
}
