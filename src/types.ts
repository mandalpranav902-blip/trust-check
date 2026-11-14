export type Verdict = 'safe' | 'suspicious' | 'scam';

export type FlagCategory = 'url' | 'text' | 'upi';

export interface RuleFlag {
  id: string;
  label: string;
  weight: number;
  evidence: string;
  category: FlagCategory;
}

export interface AnalyzeResponse {
  verdict: Verdict;
  score: number;
  scam_type: string;
  flags: RuleFlag[];
  explanation: string;
  actions: string[];
  ai_used: boolean;
}

export interface SamplePreset {
  id: string;
  label: string;
  shortHint: string;
  content: string;
}
