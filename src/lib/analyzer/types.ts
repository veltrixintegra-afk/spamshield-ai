/* ============================================================
   MOTOR DE ANÁLISIS DE CORREOS - SPAMSHIELD AI
   Motor experto propio para detección de spam, phishing,
   voiceship, y contenido generado por IA.
   ============================================================ */

export interface AnalysisResult {
  isSpam: boolean
  spamScore: number
  isAiGenerated: boolean
  aiConfidence: number
  threatType: 'phishing' | 'voiceship' | 'spoofing' | 'malware' | 'social_engineering' | 'none'
  senderAnalysis: string
  summary: string
  detailedAnalysis: string
  recommendations: string
}

export interface EmailInput {
  content: string
  sender?: string | null
  senderName?: string | null
  subject?: string | null
}

export interface Signal {
  type: 'spam' | 'phishing' | 'voiceship' | 'ai' | 'spoofing' | 'social' | 'safe'
  weight: number
  description: string
  evidence?: string
}
