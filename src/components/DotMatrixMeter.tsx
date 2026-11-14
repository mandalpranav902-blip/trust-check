import { Verdict } from '../types';

interface DotMatrixMeterProps {
  score: number;
  verdict: Verdict;
}

const VERDICT_META: Record<
  Verdict,
  { label: string; colorClass: string; thresholdText: string }
> = {
  safe: {
    label: 'LOW RISK · SAFE',
    colorClass: 'text-[#1f9d6b]',
    thresholdText: 'Threshold < 30',
  },
  suspicious: {
    label: 'MODERATE RISK · SUSPICIOUS',
    colorClass: 'text-[#d98a00]',
    thresholdText: 'Threshold 30–64',
  },
  scam: {
    label: 'HIGH RISK · SCAM',
    colorClass: 'text-[#d92d20]',
    thresholdText: 'Threshold >= 65',
  },
};

export function DotMatrixMeter({ score, verdict }: DotMatrixMeterProps) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const meta = VERDICT_META[verdict];

  return (
    <div
      className="flex flex-col justify-between rounded-[8px] border border-[#e6e6ea] bg-[#fafafa] p-5"
      role="meter"
      aria-label="Deterministic risk score meter"
      aria-valuenow={clampedScore}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className="flex items-baseline justify-between gap-4 border-b border-[#e6e6ea] pb-3">
        <div>
          <p className="type-12 font-medium tracking-wide text-[#52525b] uppercase">
            Risk Telemetry
          </p>
          <p className={`type-12 mt-0.5 font-semibold tracking-wide ${meta.colorClass}`}>
            {meta.label}
          </p>
        </div>
        <div className="text-right">
          <span className="font-display type-32 font-bold tracking-tight text-[#0b0b0e] tabular-nums">
            {clampedScore}
          </span>
          <span className="type-14 ml-1 font-mono text-[#52525b] tabular-nums">/100</span>
        </div>
      </div>

      {/* 10x10 Dot-Matrix Grid (100 dots) */}
      <div className="my-4 flex items-center justify-center">
        <div
          className="grid grid-cols-10 gap-1.5"
          aria-hidden="true"
        >
          {Array.from({ length: 100 }, (_, idx) => {
            const isFilled = idx < clampedScore;
            // Sequential fill animation settling within ~200ms total
            const delayMs = isFilled ? Math.round((idx / Math.max(1, clampedScore)) * 180) : 0;

            return (
              <span
                key={idx}
                style={{ transitionDelay: `${delayMs}ms` }}
                className={`block h-2.5 w-2.5 rounded-full instrument-transition ${
                  isFilled
                    ? 'scale-100 bg-[#ff4a1f] opacity-100'
                    : 'scale-95 bg-[#0b0b0e] opacity-[0.12]'
                }`}
              />
            );
          })}
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-[#e6e6ea] pt-2.5 type-12 text-[#52525b] tabular-nums">
        <span>0–29 Safe</span>
        <span aria-hidden="true">·</span>
        <span>30–64 Suspicious</span>
        <span aria-hidden="true">·</span>
        <span>65–100 Scam</span>
      </div>
    </div>
  );
}
