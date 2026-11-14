import { RuleFlag } from '../types';

interface HighlightedEvidenceTextProps {
  text: string;
  flags: RuleFlag[];
  activeFlagId: string | null;
  onHoverFlag: (id: string | null) => void;
}

interface TextSegment {
  text: string;
  matchedFlag?: RuleFlag;
}

function segmentTextByEvidence(sourceText: string, flags: RuleFlag[]): TextSegment[] {
  if (!sourceText) return [];
  const validFlags = flags.filter((f) => f.evidence && f.evidence.trim().length > 0);
  if (validFlags.length === 0) {
    return [{ text: sourceText }];
  }

  interface MatchSpan {
    start: number;
    end: number;
    flag: RuleFlag;
  }

  const lowerSource = sourceText.toLowerCase();
  const spans: MatchSpan[] = [];

  for (const flag of validFlags) {
    const needle = flag.evidence.toLowerCase();
    if (!needle) continue;

    let searchStart = 0;
    while (searchStart < lowerSource.length) {
      const idx = lowerSource.indexOf(needle, searchStart);
      if (idx === -1) break;
      spans.push({
        start: idx,
        end: idx + needle.length,
        flag,
      });
      searchStart = idx + needle.length;
    }
  }

  if (spans.length === 0) {
    return [{ text: sourceText }];
  }

  // Sort by start position ascending, then by longest match descending
  spans.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));

  // Merge/filter non-overlapping spans
  const nonOverlapping: MatchSpan[] = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start >= cursor) {
      nonOverlapping.push(span);
      cursor = span.end;
    }
  }

  const segments: TextSegment[] = [];
  let pos = 0;
  for (const span of nonOverlapping) {
    if (span.start > pos) {
      segments.push({ text: sourceText.slice(pos, span.start) });
    }
    segments.push({
      text: sourceText.slice(span.start, span.end),
      matchedFlag: span.flag,
    });
    pos = span.end;
  }
  if (pos < sourceText.length) {
    segments.push({ text: sourceText.slice(pos) });
  }

  return segments;
}

export function HighlightedEvidenceText({
  text,
  flags,
  activeFlagId,
  onHoverFlag,
}: HighlightedEvidenceTextProps) {
  const segments = segmentTextByEvidence(text, flags);

  return (
    <div className="rounded-[8px] border border-[#e6e6ea] bg-[#fafafa] p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="type-12 font-semibold tracking-wide text-[#52525b] uppercase">
          Inspected Payload · Matched Evidence Highlighted
        </span>
        <span className="type-12 font-mono text-[#52525b] tabular-nums">
          {flags.length} {flags.length === 1 ? 'signal' : 'signals'} matched
        </span>
      </div>
      <p className="type-16 font-mono leading-relaxed break-words whitespace-pre-wrap text-[#0b0b0e]">
        {segments.map((seg, index) => {
          if (!seg.matchedFlag) {
            return <span key={index}>{seg.text}</span>;
          }
          const flag = seg.matchedFlag;
          const isHighlighted = activeFlagId === flag.id;

          return (
            <mark
              key={index}
              onMouseEnter={() => onHoverFlag(flag.id)}
              onMouseLeave={() => onHoverFlag(null)}
              title={`${flag.label} (+${flag.weight})`}
              className={` cursor-pointer rounded-[4px] px-1 py-0.5 font-medium underline decoration-[#ff4a1f] decoration-2 underline-offset-4 instrument-transition ${
                isHighlighted
                  ? 'bg-[#ff4a1f] text-white'
                  : 'bg-[#ff4a1f]/15 text-[#0b0b0e] hover:bg-[#ff4a1f]/25'
              }`}
            >
              {seg.text}
            </mark>
          );
        })}
      </p>
    </div>
  );
}
