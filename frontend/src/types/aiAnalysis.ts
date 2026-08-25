/** AI analysis types — field-level mirror of backend AIAnalysisRead (Step 10.7). */

export interface AIAnalysis {
  id: string
  alert_group_id: string
  provider: string
  model: string
  summary: string
  attack_type: string
  why_risky: string[]
  confidence: number
  created_at: string
}
