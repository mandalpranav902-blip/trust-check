import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Info,
  OctagonAlert,
  PhoneCall,
  RotateCcw,
} from 'lucide-react';
import { useState } from 'react';
import { AnalyzeResponse, FlagCategory, RuleFlag, Verdict } from '../types';
import { DotMatrixMeter } from './DotMatrixMeter';
import { HighlightedEvidenceText } from './HighlightedEvidenceText';

interface ResultPanelProps {
  inspectedText: string;
  result: AnalyzeResponse | null;
  isLoading: boolean;
  error: string | null;
  onRetry: () => void;
}

const VERDICT_CONFIG: Record<
  Verdict,
  {
    bannerTitle: string;
    hinglishCue: string;
    textColor: string;
    borderColor: string;
    bgTint: string;
    Icon: typeof CheckCircle2;
  }
> = {
  safe: {
    bannerTitle: 'Safe · No High-Risk Signals',
    hinglishCue: 'Sab theek lag raha hai, par सतर्क रहें।',
    textColor: 'text-[#1f9d6b]',
    borderColor: 'border-[#1f9d6b]/30',
    bgTint: 'bg-[#1f9d6b]/[0.06]',
    Icon: CheckCircle2,
  },
  suspicious: {
    bannerTitle: 'Suspicious · Verify Independently',
    hinglishCue: 'Ruko. Socho. Bina jaanche click mat karo.',
    textColor: 'text-[#d98a00]',
    borderColor: 'border-[#d98a00]/35',
    bgTint: 'bg-[#d98a00]/[0.07]',
    Icon: AlertTriangle,
  },
  scam: {
    bannerTitle: 'Scam Detected · Do Not Interact',
    hinglishCue: 'Savdhaan! Yeh ek scam pattern hai.',
    textColor: 'text-[#d92d20]',
    borderColor: 'border-[#d92d20]/35',
    bgTint: 'bg-[#d92d20]/[0.06]',
    Icon: OctagonAlert,
  },
};

const CATEGORY_LABELS: Record<FlagCategory, string> = {
  url: 'URL & Domain Signals',
  text: 'Language & Coercion Signals',
  upi: 'UPI & Payment Signals',
};

const CATEGORY_ORDER: FlagCategory[] = ['url', 'upi', 'text'];

export function ResultPanel({
  inspectedText,
  result,
  isLoading,
  error,
  onRetry,
}: ResultPanelProps) {
  const [activeFlagId, setActiveFlagId] = useState<string | null>(null);

  // 1. Loading Skeleton State
  if (isLoading) {
    return (
      <section
        aria-busy="true"
        aria-label="Analyzing input"
        className="rounded-[8px] border border-[#e6e6ea] bg-white p-6 text-[#0b0b0e] md:p-8"
      >
        <div className="flex flex-col gap-6">
          <div className="flex items-center justify-between border-b border-[#e6e6ea] pb-5">
            <div className="space-y-2">
              <div className="h-4 w-36 animate-pulse rounded bg-[#e6e6ea]" />
              <div className="h-7 w-72 animate-pulse rounded bg-[#e6e6ea]" />
            </div>
            <div className="h-10 w-24 animate-pulse rounded bg-[#e6e6ea]" />
          </div>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="h-64 animate-pulse rounded-[8px] bg-[#f4f4f6] lg:col-span-4" />
            <div className="space-y-4 lg:col-span-8">
              <div className="h-28 animate-pulse rounded-[8px] bg-[#f4f4f6]" />
              <div className="h-32 animate-pulse rounded-[8px] bg-[#f4f4f6]" />
            </div>
          </div>
        </div>
      </section>
    );
  }

  // 2. Error State with Retry
  if (error) {
    return (
      <section
        role="alert"
        className="rounded-[8px] border border-[#e6e6ea] bg-white p-6 text-[#0b0b0e] md:p-8"
      >
        <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-[#d92d20]" aria-hidden="true" />
            <div>
              <h2 className="font-display type-20 font-semibold text-[#0b0b0e]">
                Inspection Could Not Complete
              </h2>
              <p className="type-14 mt-1 text-[#52525b]">{error}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-2 rounded-[6px] bg-[#0b0b0e] px-4 py-2 type-14 font-medium text-white whitespace-nowrap shrink-0 hover:bg-[#27272a] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition cursor-pointer"
          >
            <RotateCcw className="h-4 w-4" aria-hidden="true" />
            Retry Analysis
          </button>
        </div>
      </section>
    );
  }

  // 3. Empty Standby State
  if (!result) {
    return (
      <section
        aria-label="Inspection instrument standby"
        className="rounded-[8px] border border-[rgba(255,255,255,0.10)] bg-[#0b0b0e] p-6 md:p-8"
      >
        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          <div>
            <p className="type-12 font-mono text-[#8a8a93] uppercase">Stage 01 · Evidence</p>
            <h2 className="font-display type-20 mt-1 font-semibold text-[#f4f4f6]">
              Deterministic Extraction
            </h2>
            <p className="type-14 mt-1.5 text-[#8a8a93]">
              Extracts URLs, bare SMS domains, UPI VPAs, phone numbers, and INR amounts directly from raw text.
            </p>
          </div>
          <div>
            <p className="type-12 font-mono text-[#8a8a93] uppercase">Stage 02 · Interpretation</p>
            <h2 className="font-display type-20 mt-1 font-semibold text-[#f4f4f6]">
              India-Calibrated Rules
            </h2>
            <p className="type-14 mt-1.5 text-[#8a8a93]">
              Checks lookalike domains (SBI, HDFC, India Post, BESCOM), UPI PIN-to-receive lures, and English/Hindi/Hinglish threats.
            </p>
          </div>
          <div>
            <p className="type-12 font-mono text-[#8a8a93] uppercase">Stage 03 · Verdict</p>
            <h2 className="font-display type-20 mt-1 font-semibold text-[#f4f4f6]">
              Auditable Score (0–100)
            </h2>
            <p className="type-14 mt-1.5 text-[#8a8a93]">
              Every point on the 100-dot risk matrix maps to an exact matched substring. AI explains the result but never alters the score.
            </p>
          </div>
        </div>
      </section>
    );
  }

  const vConfig = VERDICT_CONFIG[result.verdict];
  const VerdictIcon = vConfig.Icon;

  // Group flags by category
  const groupedFlags = CATEGORY_ORDER.map((cat) => ({
    category: cat,
    title: CATEGORY_LABELS[cat],
    items: result.flags.filter((f) => f.category === cat),
  })).filter((group) => group.items.length > 0);

  return (
    <section
      aria-label="Analysis Result"
      className="rounded-[8px] border border-[#e6e6ea] bg-white p-6 text-[#0b0b0e] md:p-8"
    >
      {/* 1. Verdict Banner (Colour used sparingly and paired with Icon + Explicit Text) */}
      <div
        className={`flex flex-col justify-between gap-4 rounded-[8px] border p-5 sm:flex-row sm:items-center ${vConfig.borderColor} ${vConfig.bgTint}`}
      >
        <div className="flex items-start gap-3.5">
          <VerdictIcon
            className={`mt-1 h-7 w-7 shrink-0 ${vConfig.textColor}`}
            aria-hidden="true"
          />
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`font-display type-32 font-bold tracking-tight ${vConfig.textColor}`}>
                {vConfig.bannerTitle}
              </span>
            </div>
            <p className="type-14 mt-1 font-medium text-[#0b0b0e]">
              Classification: <span className="font-semibold">{result.scam_type}</span>
              <span className="mx-2 text-[#8a8a93]" aria-hidden="true">
                ·
              </span>
              <span className="text-[#52525b] italic">{vConfig.hinglishCue}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center">
          <span className="type-12 font-mono text-[#52525b] uppercase">
            {result.ai_used ? 'Rules + AI Synthesis' : 'Rules-Only Verdict'}
          </span>
        </div>
      </div>

      {/* Rules-only fallback notice when AI explanation is unavailable */}
      {!result.ai_used && (
        <div
          role="status"
          className="mt-4 flex items-center gap-2.5 rounded-[6px] border border-[#e6e6ea] bg-[#fafafa] px-4 py-2.5 type-14 text-[#52525b]"
        >
          <Info className="h-4 w-4 shrink-0 text-[#0b0b0e]" aria-hidden="true" />
          <span>
            <strong className="font-medium text-[#0b0b0e]">
              AI explanation unavailable, rules-only result:
            </strong>{' '}
            This verdict, score, and summary were generated deterministically by the local rule engine.
          </span>
        </div>
      )}

      {/* 2. Evidence -> Interpretation -> Verdict Grid */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: 100-dot Dot-Matrix Risk Meter */}
        <div className="lg:col-span-4">
          <DotMatrixMeter score={result.score} verdict={result.verdict} />
        </div>

        {/* Right Column: Plain-Language Explanation & Highlighted Original Text */}
        <div className="flex flex-col justify-between gap-5 lg:col-span-8">
          <div className="rounded-[8px] border border-[#e6e6ea] bg-white p-5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="type-12 font-semibold tracking-wide text-[#52525b] uppercase">
                Interpretation · Plain-Language Assessment
              </h3>
              <span className="type-12 font-mono text-[#52525b]">
                {result.scam_type}
              </span>
            </div>
            <p className="type-16 mt-2.5 leading-relaxed text-[#0b0b0e]">
              {result.explanation}
            </p>
          </div>

          <HighlightedEvidenceText
            text={inspectedText}
            flags={result.flags}
            activeFlagId={activeFlagId}
            onHoverFlag={setActiveFlagId}
          />
        </div>
      </div>

      {/* 3. Matched Flags Grouped by Category */}
      <div className="mt-8 border-t border-[#e6e6ea] pt-6">
        <div className="flex items-baseline justify-between gap-4">
          <h3 className="font-display type-20 font-semibold text-[#0b0b0e]">
            Matched Evidence Signals
          </h3>
          <span className="type-12 font-mono text-[#52525b] tabular-nums">
            {result.flags.length === 0
              ? '0 rules triggered'
              : `${result.flags.length} ${result.flags.length === 1 ? 'rule' : 'rules'} triggered`}
          </span>
        </div>

        {groupedFlags.length === 0 ? (
          <p className="type-14 mt-3 text-[#52525b]">
            No deceptive URLs, coercive threat patterns, or suspicious UPI instructions were matched in this input.
          </p>
        ) : (
          <div className="mt-4 grid grid-cols-1 gap-5 md:grid-cols-2">
            {groupedFlags.map((group) => (
              <div
                key={group.category}
                className="rounded-[8px] border border-[#e6e6ea] bg-[#fafafa] p-4"
              >
                <div className="flex items-center justify-between border-b border-[#e6e6ea] pb-2.5">
                  <h4 className="type-12 font-semibold tracking-wide text-[#0b0b0e] uppercase">
                    {group.title}
                  </h4>
                  <span className="type-12 font-mono text-[#52525b] tabular-nums">
                    {group.items.length}
                  </span>
                </div>
                <ul className="mt-3 divide-y divide-[#e6e6ea]">
                  {group.items.map((flag: RuleFlag) => {
                    const isHovered = activeFlagId === flag.id;
                    return (
                      <li
                        key={flag.id}
                        onMouseEnter={() => setActiveFlagId(flag.id)}
                        onMouseLeave={() => setActiveFlagId(null)}
                        className={`py-2.5 first:pt-0 last:pb-0 instrument-transition ${
                          isHovered ? 'bg-[#ff4a1f]/[0.06] -mx-2 px-2 rounded-[4px]' : ''
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <p className="type-14 font-medium text-[#0b0b0e]">{flag.label}</p>
                          <span className="type-12 shrink-0 font-mono font-semibold text-[#ff4a1f] tabular-nums">
                            +{flag.weight}
                          </span>
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-2 type-12 text-[#52525b]">
                          <span>Matched evidence:</span>
                          <code className="rounded bg-white px-1.5 py-0.5 font-mono text-[#0b0b0e] border border-[#e6e6ea]">
                            {flag.evidence}
                          </code>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono text-[#8a8a93]">{flag.id}</span>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. What to Do Now & Official Cybercrime Reporting Card */}
      <div className="mt-8 grid grid-cols-1 gap-6 border-t border-[#e6e6ea] pt-6 lg:grid-cols-12">
        {/* What to do now */}
        <div className="lg:col-span-7">
          <h3 className="font-display type-20 font-semibold text-[#0b0b0e]">
            What to do now
          </h3>
          <ol className="mt-3 space-y-2.5">
            {result.actions.map((action, idx) => (
              <li
                key={idx}
                className="flex items-start gap-3 rounded-[6px] border border-[#e6e6ea] bg-[#fafafa] p-3.5"
              >
                <span className="type-12 mt-0.5 font-mono font-semibold text-[#ff4a1f] tabular-nums">
                  0{idx + 1}.
                </span>
                <span className="type-14 text-[#0b0b0e]">{action}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Report It Card (cybercrime.gov.in + 1930 helpline) */}
        <div className="lg:col-span-5">
          <div className="flex h-full flex-col justify-between rounded-[8px] border border-[#e6e6ea] bg-[#fafafa] p-5">
            <div>
              <p className="type-12 font-semibold tracking-wide text-[#52525b] uppercase">
                Official Indian Helplines
              </p>
              <h3 className="font-display type-20 mt-1 font-semibold text-[#0b0b0e]">
                Report it immediately
              </h3>
              <p className="type-14 mt-2 text-[#52525b]">
                If money was debited or you shared an OTP/UPI PIN, reporting within the golden hour maximizes the chance of freezing the fraudulent transfer.
              </p>
            </div>

            <div className="mt-5 space-y-2.5">
              <a
                href="tel:1930"
                className="flex w-full items-center justify-between rounded-[6px] border border-[#0b0b0e] bg-[#0b0b0e] px-4 py-2.5 type-14 font-medium text-white hover:bg-[#27272a] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition"
              >
                <span className="inline-flex items-center gap-2 whitespace-nowrap">
                  <PhoneCall className="h-4 w-4 text-[#ff4a1f]" aria-hidden="true" />
                  Dial 1930 (24×7 Cyber Helpline)
                </span>
                <span className="font-mono type-12 text-[#8a8a93] tabular-nums">Toll-Free</span>
              </a>

              <a
                href="https://cybercrime.gov.in"
                target="_blank"
                rel="noopener noreferrer"
                className="flex w-full items-center justify-between rounded-[6px] border border-[#e6e6ea] bg-white px-4 py-2.5 type-14 font-medium text-[#0b0b0e] hover:border-[#0b0b0e] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition"
              >
                <span className="whitespace-nowrap">File Report at cybercrime.gov.in</span>
                <ExternalLink className="h-4 w-4 text-[#52525b]" aria-hidden="true" />
              </a>

              <a
                href="https://sancharsaathi.gov.in/sfc/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex w-full items-center justify-between rounded-[6px] border border-[#e6e6ea] bg-white px-4 py-2.5 type-14 font-medium text-[#0b0b0e] hover:border-[#0b0b0e] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition"
              >
                <span className="whitespace-nowrap">Report Fraud SMS on Chakshu Portal</span>
                <ExternalLink className="h-4 w-4 text-[#52525b]" aria-hidden="true" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
