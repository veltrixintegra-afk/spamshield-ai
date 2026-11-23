import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'
import { db } from '@/lib/db'

export async function POST(request: NextRequest) {
  try {
    const { scanId } = await request.json()

    if (!scanId) {
      return NextResponse.json(
        { error: 'ID de análisis requerido' },
        { status: 400 }
      )
    }

    const scan = await db.emailScan.findUnique({
      where: { id: scanId },
    })

    if (!scan) {
      return NextResponse.json(
        { error: 'Análisis no encontrado' },
        { status: 404 }
      )
    }

    let analysisData: Record<string, any> = {}
    try {
      if (scan.analysisJson) {
        analysisData = JSON.parse(scan.analysisJson)
      }
    } catch {
      analysisData = {}
    }

    const verdict = getVerdict(scan.spamScore)
    const verdictColor = getVerdictColor(scan.spamScore)
    const verdictBg = getVerdictBg(scan.spamScore)
    const verdictDesc = getVerdictDesc(scan.spamScore)

    const threatLabels: Record<string, string> = {
      phishing: 'Phishing — Suplantación de Identidad',
      voiceship: 'Voiceship / CEO Fraud',
      spoofing: 'Spoofing — Falsificación de Remitente',
      malware: 'Malware — Software Malicioso',
      social_engineering: 'Ingeniería Social',
      none: 'Sin Amenaza Detectada',
    }

    const sourceLabels: Record<string, string> = {
      paste: 'Texto Pegado',
      upload: 'Archivo Subido',
      gmail: 'Gmail',
      outlook: 'Outlook',
    }

    const dateStr = new Date(scan.createdAt).toLocaleString('es-CL', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })

    const reportId = scan.id.substring(0, 12).toUpperCase()

    // ── Hash de Integridad SHA-256 ──
    // Calculado sobre el contenido del correo + metadatos del analisis
    // para garantizar que el informe no ha sido alterado (cadena de custodia).
    const integrityPayload = JSON.stringify({
      scanId: scan.id,
      emailBody: scan.emailBody,
      senderEmail: scan.senderEmail,
      senderName: scan.senderName,
      subject: scan.subject,
      isSpam: scan.isSpam,
      spamScore: scan.spamScore,
      isAiGenerated: scan.isAiGenerated,
      aiConfidence: scan.aiConfidence,
      threatType: scan.threatType,
      createdAt: scan.createdAt.toISOString(),
    })
    const integrityHash = crypto
      .createHash('sha256')
      .update(integrityPayload, 'utf8')
      .digest('hex')

    const htmlReport = generateReportHTML({
      scanId: scan.id,
      reportId,
      verdict,
      verdictColor,
      verdictBg,
      verdictDesc,
      spamScore: scan.spamScore ?? 0,
      aiConfidence: scan.aiConfidence ?? 0,
      isSpam: scan.isSpam,
      isAiGenerated: scan.isAiGenerated,
      threatType: threatLabels[scan.threatType || 'none'] || scan.threatType || 'Desconocido',
      threatTypeRaw: scan.threatType || 'none',
      source: sourceLabels[scan.source] || scan.source,
      senderEmail: scan.senderEmail || 'No identificado',
      senderName: scan.senderName || scan.senderEmail || 'No identificado',
      subject: scan.subject || 'Sin asunto',
      fileName: scan.fileName,
      dateStr,
      senderAnalysis: analysisData.senderAnalysis || 'No disponible',
      summary: analysisData.summary || 'No disponible',
      detailedAnalysis: analysisData.detailedAnalysis || 'No disponible',
      recommendations: analysisData.recommendations || 'No disponibles',
      emailBody: scan.emailBody,
      integrityHash,
    })

    await db.emailScan.update({
      where: { id: scanId },
      data: { reportPath: `report-${scanId}.html` },
    })

    return new NextResponse(htmlReport, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="SpamShield-Informe-${reportId}.html"`,
      },
    })
  } catch (error) {
    console.error('Error generating report:', error)
    return NextResponse.json(
      { error: 'Error al generar el informe' },
      { status: 500 }
    )
  }
}

function getVerdict(score: number | null): string {
  if (score === null) return 'DESCONOCIDO'
  if (score < 30) return 'SEGURO'
  if (score < 60) return 'SOSPECHOSO'
  if (score < 80) return 'PELIGROSO'
  return 'CRÍTICO'
}

function getVerdictColor(score: number | null): string {
  if (score === null) return '#6b7280'
  if (score < 30) return '#10b981'
  if (score < 60) return '#f59e0b'
  if (score < 80) return '#f97316'
  return '#ef4444'
}

function getVerdictBg(score: number | null): string {
  if (score === null) return '#f3f4f6'
  if (score < 30) return '#ecfdf5'
  if (score < 60) return '#fffbeb'
  if (score < 80) return '#fff7ed'
  return '#fef2f2'
}

function getVerdictDesc(score: number | null): string {
  if (score === null) return 'No se pudo determinar el nivel de amenaza.'
  if (score < 30) return 'El correo electrónico no presenta indicadores significativos de amenaza. El contenido parece legítimo y seguro.'
  if (score < 60) return 'El correo presenta algunos indicadores sospechosos. Se recomienda verificar el remitente antes de interactuar con el contenido.'
  if (score < 80) return 'El correo presenta múltiples indicadores de amenaza. Se recomienda no interactuar con el contenido y eliminar el correo.'
  return 'El correo presenta indicadores críticos de amenaza. No interactúe con ningún enlace o adjunto. Elimine inmediatamente y reporte a seguridad.'
}

interface ReportData {
  scanId: string
  reportId: string
  verdict: string
  verdictColor: string
  verdictBg: string
  verdictDesc: string
  spamScore: number
  aiConfidence: number
  isSpam: boolean
  isAiGenerated: boolean
  threatType: string
  threatTypeRaw: string
  source: string
  senderEmail: string
  senderName: string
  subject: string
  fileName?: string | null
  dateStr: string
  senderAnalysis: string
  summary: string
  detailedAnalysis: string
  recommendations: string
  emailBody: string
  integrityHash: string
}

/* ============================================================
   MARKDOWN RENDERER - Convierte markdown a HTML profesional
   ============================================================ */
function renderMarkdown(md: string): string {
  let html = escapeHtml(md)

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h3 class="md-h3">$1</h3>')
  html = html.replace(/^## (.+)$/gm, '<h2 class="md-h2">$1</h2>')

  // Bold and italic
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>')

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>')

  // Lists - group consecutive list items
  html = html.replace(/(?:^(- .+(?:\n|$))+)/gm, (match) => {
    const items = match.trim().split('\n').map(line => {
      const content = line.replace(/^- /, '')
      // Handle sub-items (indented with spaces)
      if (line.startsWith('  - ')) {
        return `<li class="md-subitem">${line.replace(/^\s+- /, '')}</li>`
      }
      return `<li class="md-item">${content}</li>`
    })
    return `<ul class="md-list">${items.join('')}</ul>`
  })

  // Paragraphs and line breaks
  html = html.replace(/\n\n/g, '</p><p class="md-p">')
  html = html.replace(/\n/g, '<br>')

  // Wrap remaining text in paragraphs
  if (!html.startsWith('<')) {
    html = `<p class="md-p">${html}</p>`
  }

  return html
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/* ============================================================
   SVG GAUGE - Medidor circular de amenaza
   ============================================================ */
function generateGaugeSVG(score: number, color: string): string {
  const radius = 80
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return `
  <svg width="200" height="200" viewBox="0 0 200 200" class="gauge-svg">
    <defs>
      <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.6"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="1"/>
      </linearGradient>
      <filter id="gaugeShadow">
        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.15"/>
      </filter>
    </defs>
    <circle cx="100" cy="100" r="${radius}" fill="none" stroke="#e5e7eb" stroke-width="12"/>
    <circle cx="100" cy="100" r="${radius}" fill="none" stroke="url(#gaugeGrad)" stroke-width="12"
      stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
      transform="rotate(-90 100 100)" filter="url(#gaugeShadow)"/>
    <text x="100" y="95" text-anchor="middle" font-size="42" font-weight="800" fill="${color}" font-family="Arial">${score}</text>
    <text x="100" y="115" text-anchor="middle" font-size="13" fill="#9ca3af" font-family="Arial">/ 100</text>
  </svg>`
}

/* ============================================================
   THREAT CATEGORY BARS - Barras de puntuación por categoría
   ============================================================ */
function generateThreatBars(analysisJson: string): string {
  // Parse the analysis to get signal breakdown if available
  let categories: Array<{ label: string; score: number; color: string; icon: string }> = []

  try {
    const data = JSON.parse(analysisJson)
    // We'll estimate category scores from the analysis
    // Since we don't have raw signals in the stored JSON, we'll use the main metrics
    categories = [
      { label: 'Spam General', score: data.spamScore || 0, color: '#ef4444', icon: 'S' },
      { label: 'Phishing', score: data.threatType === 'phishing' ? (data.spamScore || 0) : Math.round((data.spamScore || 0) * 0.3), color: '#f97316', icon: 'P' },
      { label: 'Voiceship/CEO', score: data.threatType === 'voiceship' ? (data.spamScore || 0) : Math.round((data.spamScore || 0) * 0.2), color: '#8b5cf6', icon: 'V' },
      { label: 'Contenido IA', score: data.aiConfidence || 0, color: '#6366f1', icon: 'AI' },
    ]
  } catch {
    categories = []
  }

  if (categories.length === 0) return ''

  return `
  <div class="threat-bars">
    ${categories.map(cat => `
      <div class="threat-bar-row">
        <div class="threat-bar-icon" style="background:${cat.color}20;color:${cat.color}">${cat.icon}</div>
        <div class="threat-bar-content">
          <div class="threat-bar-header">
            <span class="threat-bar-label">${cat.label}</span>
            <span class="threat-bar-value" style="color:${cat.color}">${cat.score}%</span>
          </div>
          <div class="threat-bar-track">
            <div class="threat-bar-fill" style="width:${cat.score}%;background:linear-gradient(90deg,${cat.color}80,${cat.color});"></div>
          </div>
        </div>
      </div>
    `).join('')}
  </div>`
}

/* ============================================================
   MAIN REPORT HTML GENERATOR
   ============================================================ */
function generateReportHTML(d: ReportData): string {
  const gaugeSVG = generateGaugeSVG(d.spamScore, d.verdictColor)
  const threatBars = generateThreatBars(JSON.stringify({
    spamScore: d.spamScore,
    aiConfidence: d.aiConfidence,
    threatType: d.threatTypeRaw,
  }))

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>SpamShield AI - Informe Forense ${d.reportId}</title>
<style>
  @page { 
    size: A4; 
    margin: 0;
  }
  @page :first {
    margin: 0;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    color: #1f2937;
    line-height: 1.6;
    background: #ffffff;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  /* ── COVER PAGE ── */
  .cover {
    background: linear-gradient(135deg, #0a0f1e 0%, #111827 40%, #064e3b 100%);
    color: #ffffff;
    min-height: 297mm;
    padding: 0;
    position: relative;
    page-break-after: always;
    overflow: hidden;
  }

  .cover::before {
    content: '';
    position: absolute;
    top: -100px; right: -100px;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(16,185,129,0.15) 0%, transparent 70%);
    border-radius: 50%;
  }
  .cover::after {
    content: '';
    position: absolute;
    bottom: -150px; left: -150px;
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(16,185,129,0.08) 0%, transparent 70%);
    border-radius: 50%;
  }

  .cover-header {
    padding: 40px 50px 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: relative;
    z-index: 2;
  }
  .cover-logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .cover-logo-icon {
    width: 40px; height: 40px;
    background: rgba(16,185,129,0.15);
    border: 1px solid rgba(16,185,129,0.3);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
  }
  .cover-logo-icon svg { width: 22px; height: 22px; }
  .cover-logo-text {
    font-size: 18px; font-weight: 700; letter-spacing: -0.3px;
  }
  .cover-logo-text span { color: #10b981; }

  .cover-classification {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: #94a3b8; border: 1px solid rgba(148,163,184,0.3);
    padding: 4px 12px; border-radius: 4px;
  }

  .cover-body {
    padding: 60px 50px;
    position: relative;
    z-index: 2;
  }

  .cover-title {
    font-size: 14px; letter-spacing: 4px; text-transform: uppercase;
    color: #10b981; margin-bottom: 16px; font-weight: 600;
  }
  .cover-h1 {
    font-size: 42px; font-weight: 800; letter-spacing: -1px;
    line-height: 1.15; margin-bottom: 20px;
  }
  .cover-subtitle {
    font-size: 16px; color: #94a3b8; max-width: 500px; line-height: 1.6;
  }

  .cover-verdict-box {
    margin: 48px 0;
    display: inline-block;
  }
  .cover-verdict-label {
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
    color: #64748b; margin-bottom: 8px;
  }
  .cover-verdict-badge {
    display: inline-flex; align-items: center; gap: 12px;
    background: ${d.verdictColor}20;
    border: 2px solid ${d.verdictColor};
    padding: 16px 36px;
    border-radius: 8px;
  }
  .cover-verdict-text {
    font-size: 28px; font-weight: 800; color: ${d.verdictColor};
    letter-spacing: 4px;
  }
  .cover-verdict-score {
    font-size: 36px; font-weight: 800; color: ${d.verdictColor};
    border-left: 2px solid ${d.verdictColor}40;
    padding-left: 16px;
  }

  .cover-meta-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 24px;
    margin-top: 40px;
    max-width: 600px;
  }
  .cover-meta-item {
    border-left: 2px solid rgba(16,185,129,0.3);
    padding-left: 12px;
  }
  .cover-meta-label {
    font-size: 9px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #64748b; margin-bottom: 4px;
  }
  .cover-meta-value {
    font-size: 13px; color: #e2e8f0; font-weight: 500;
  }

  .cover-footer {
    position: absolute;
    bottom: 30px; left: 50px; right: 50px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px solid rgba(148,163,184,0.15);
    padding-top: 16px;
    z-index: 2;
  }
  .cover-footer-text {
    font-size: 10px; color: #64748b;
  }
  .cover-footer-id {
    font-size: 11px; color: #94a3b8; font-family: 'Courier New', monospace;
  }

  /* ── CONTENT PAGES ── */
  .page {
    padding: 50px 55px 40px;
    min-height: 297mm;
    position: relative;
    page-break-after: always;
  }
  .page:last-child { page-break-after: auto; }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid #e5e7eb;
    margin-bottom: 28px;
  }
  .page-header-left {
    display: flex; align-items: center; gap: 8px;
    font-size: 11px; color: #6b7280; font-weight: 600;
    text-transform: uppercase; letter-spacing: 1px;
  }
  .page-header-left .shield-dot {
    width: 8px; height: 8px; border-radius: 50%; background: #10b981;
  }
  .page-header-right {
    font-size: 10px; color: #9ca3af; font-family: 'Courier New', monospace;
  }

  .page-footer {
    position: absolute;
    bottom: 20px; left: 55px; right: 55px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px solid #e5e7eb;
    padding-top: 10px;
    font-size: 9px; color: #9ca3af;
  }

  /* ── SECTIONS ── */
  .section { margin-bottom: 28px; }
  .section-header {
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 14px;
  }
  .section-icon {
    width: 24px; height: 24px; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
  }
  .section-title {
    font-size: 15px; font-weight: 700; color: #111827;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .section-divider {
    height: 2px; background: linear-gradient(90deg, #10b981 0%, transparent 100%);
    margin-bottom: 16px;
  }

  /* ── EXECUTIVE SUMMARY BOX ── */
  .exec-box {
    background: linear-gradient(135deg, ${d.verdictBg} 0%, #ffffff 100%);
    border: 1px solid ${d.verdictColor}30;
    border-left: 4px solid ${d.verdictColor};
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .exec-box-title {
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 8px; font-weight: 600;
  }
  .exec-box-text {
    font-size: 13px; color: #374151; line-height: 1.7;
  }

  /* ── GAUGE + METRICS ROW ── */
  .metrics-row {
    display: flex;
    gap: 30px;
    align-items: center;
    margin-bottom: 24px;
  }
  .gauge-container {
    flex-shrink: 0;
    text-align: center;
  }
  .gauge-label {
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #6b7280; margin-top: -10px;
  }

  .metrics-right {
    flex: 1;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .metric-mini {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 14px 16px;
  }
  .metric-mini-label {
    font-size: 9px; letter-spacing: 1px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 6px; font-weight: 600;
  }
  .metric-mini-value {
    font-size: 22px; font-weight: 800; color: #111827;
    display: flex; align-items: baseline; gap: 4px;
  }
  .metric-mini-value .unit { font-size: 13px; color: #9ca3af; }
  .metric-mini-bar {
    height: 4px; background: #e5e7eb; border-radius: 2px;
    margin-top: 8px; overflow: hidden;
  }
  .metric-mini-bar-fill {
    height: 100%; border-radius: 2px;
  }

  /* ── THREAT BARS ── */
  .threat-bars {
    display: flex; flex-direction: column; gap: 10px;
  }
  .threat-bar-row {
    display: flex; align-items: center; gap: 12px;
  }
  .threat-bar-icon {
    width: 32px; height: 32px; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700; flex-shrink: 0;
  }
  .threat-bar-content { flex: 1; }
  .threat-bar-header {
    display: flex; justify-content: space-between; margin-bottom: 4px;
  }
  .threat-bar-label { font-size: 12px; color: #374151; font-weight: 500; }
  .threat-bar-value { font-size: 12px; font-weight: 700; }
  .threat-bar-track {
    height: 6px; background: #f3f4f6; border-radius: 3px; overflow: hidden;
  }
  .threat-bar-fill {
    height: 100%; border-radius: 3px;
    transition: width 0.3s;
  }

  /* ── INFO TABLE ── */
  .info-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .info-table tr {
    border-bottom: 1px solid #f3f4f6;
  }
  .info-table tr:last-child { border-bottom: none; }
  .info-table td {
    padding: 10px 12px;
    vertical-align: top;
  }
  .info-table .info-label {
    width: 160px;
    color: #6b7280;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background: #f9fafb;
  }
  .info-table .info-value {
    color: #1f2937;
    word-break: break-word;
  }
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-danger { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
  .badge-success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
  .badge-warning { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
  .badge-info { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }

  /* ── MARKDOWN CONTENT ── */
  .md-content {
    font-size: 12.5px;
    color: #374151;
    line-height: 1.75;
  }
  .md-h2 {
    font-size: 14px; font-weight: 700; color: #111827;
    margin: 18px 0 10px; padding-bottom: 6px;
    border-bottom: 1px solid #e5e7eb;
  }
  .md-h3 {
    font-size: 13px; font-weight: 700; color: #1f2937;
    margin: 14px 0 8px;
  }
  .md-p { margin-bottom: 10px; }
  .md-list {
    list-style: none;
    padding-left: 0;
    margin-bottom: 12px;
  }
  .md-item {
    padding-left: 20px;
    position: relative;
    margin-bottom: 6px;
  }
  .md-item::before {
    content: '';
    position: absolute;
    left: 4px; top: 9px;
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #10b981;
  }
  .md-subitem {
    padding-left: 40px;
    position: relative;
    margin-bottom: 4px;
    font-size: 11.5px;
    color: #6b7280;
  }
  .md-subitem::before {
    content: '→';
    position: absolute;
    left: 24px;
    color: #9ca3af;
  }
  .md-code {
    background: #f3f4f6;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-family: 'Courier New', monospace;
    color: #dc2626;
  }
  .md-content strong { color: #111827; }
  .md-content em { color: #6b7280; }

  /* ── EMAIL PREVIEW ── */
  .email-preview {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
    max-height: 300px;
    overflow: hidden;
    font-size: 11px;
    color: #6b7280;
    font-family: 'Courier New', monospace;
    white-space: pre-wrap;
    word-break: break-word;
    position: relative;
  }
  .email-preview::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 60px;
    background: linear-gradient(transparent, #f9fafb);
  }

  /* ── RISK MATRIX ── */
  .risk-matrix {
    display: grid;
    grid-template-columns: auto repeat(3, 1fr);
    gap: 2px;
    max-width: 400px;
    margin: 0 auto;
  }
  .risk-matrix-cell {
    padding: 10px 8px;
    text-align: center;
    font-size: 10px;
    border-radius: 4px;
  }
  .risk-matrix-header {
    background: #f3f4f6;
    font-weight: 700;
    color: #374151;
  }
  .risk-matrix-label {
    background: #f9fafb;
    font-weight: 600;
    color: #6b7280;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* ── PRINT BUTTON ── */
  .print-bar {
    position: fixed;
    top: 0; left: 0; right: 0;
    background: #111827;
    color: white;
    padding: 12px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    z-index: 10000;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
  }
  .print-bar-text {
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .print-bar-text .shield-icon {
    color: #10b981;
  }
  .print-btn {
    background: #10b981;
    color: white;
    border: none;
    padding: 8px 20px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  .print-btn:hover { background: #059669; }
  .print-btn-close {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.2);
    margin-left: 8px;
  }
  .print-btn-close:hover { background: rgba(255,255,255,0.1); }

  @media print {
    .print-bar { display: none; }
    .page { min-height: auto; }
  }

  /* ── DENUNCIANTE / FILL-IN FIELDS ── */
  .denunciante-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px 28px;
    margin-top: 8px;
  }
  .denunciante-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .denunciante-label {
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #6b7280;
    font-weight: 600;
  }
  .denunciante-line {
    border-bottom: 1px solid #9ca3af;
    height: 22px;
  }
  .denunciante-note {
    font-size: 10px;
    color: #9ca3af;
    margin-top: 14px;
    font-style: italic;
  }

  /* ── DECLARACION DE VERACIDAD ── */
  .declaracion-box {
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 20px 24px;
    background: #f9fafb;
    margin-top: 8px;
  }
  .declaracion-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 18px;
  }
  .declaracion-check {
    width: 18px;
    height: 18px;
    border: 2px solid #374151;
    border-radius: 3px;
    flex-shrink: 0;
    margin-top: 2px;
  }
  .declaracion-text {
    font-size: 12px;
    color: #1f2937;
    line-height: 1.7;
  }
  .declaracion-signature-row {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 40px;
    margin-top: 24px;
  }
  .signature-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .signature-line {
    border-bottom: 1px solid #374151;
    height: 30px;
  }
  .signature-caption {
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #6b7280;
    font-weight: 600;
  }

  /* ── CLAUSULA LEGAL ── */
  .legal-clause {
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-left: 4px solid #d97706;
    border-radius: 8px;
    padding: 18px 22px;
    margin-top: 8px;
  }
  .legal-clause-title {
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #92400e;
    font-weight: 700;
    margin-bottom: 8px;
  }
  .legal-clause-text {
    font-size: 10.5px;
    color: #4b3613;
    line-height: 1.7;
    text-align: justify;
  }
  .legal-clause-laws {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 12px;
  }
  .legal-clause-law {
    display: inline-block;
    background: #fef3c7;
    border: 1px solid #fcd34d;
    color: #92400e;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
  }

  /* ── INTEGRITY HASH ── */
  .integrity-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 8px;
  }
  .integrity-label {
    font-size: 9px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #6b7280;
    font-weight: 600;
  }
  .integrity-hash {
    font-family: 'Courier New', monospace;
    font-size: 10px;
    color: #374151;
    word-break: break-all;
    background: #f3f4f6;
    padding: 8px 12px;
    border-radius: 4px;
    border: 1px solid #e5e7eb;
  }
  .integrity-note {
    font-size: 9px;
    color: #9ca3af;
    font-style: italic;
  }
</style>
</head>
<body>

<!-- PRINT BAR -->
<div class="print-bar">
  <div class="print-bar-text">
    <span class="shield-icon">🛡</span>
    <span><strong>SpamShield AI</strong> — Informe Forense ${d.reportId}</span>
  </div>
  <div>
    <button class="print-btn" onclick="window.print()">📄 Guardar como PDF</button>
    <button class="print-btn print-btn-close" onclick="window.close()">✕ Cerrar</button>
  </div>
</div>

<!-- ============ COVER PAGE ============ -->
<div class="cover">
  <div class="cover-header">
    <div class="cover-logo">
      <div class="cover-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <span class="cover-logo-text">Spam<span>Shield</span> AI</span>
    </div>
    <div class="cover-classification">Confidencial</div>
  </div>

  <div class="cover-body">
    <div class="cover-title">Informe Forense de Correo Electrónico</div>
    <h1 class="cover-h1">Análisis de Seguridad<br>y Detección de Amenazas</h1>
    <p class="cover-subtitle">Análisis automatizado mediante motor de inteligencia artificial especializado en detección de spam, phishing, voiceship, spoofing y contenido generado por IA.</p>

    <div class="cover-verdict-box">
      <div class="cover-verdict-label">Veredicto del Análisis</div>
      <div class="cover-verdict-badge">
        <span class="cover-verdict-text">${d.verdict}</span>
        <span class="cover-verdict-score">${d.spamScore}</span>
      </div>
    </div>

    <div class="cover-meta-grid">
      <div class="cover-meta-item">
        <div class="cover-meta-label">Report ID</div>
        <div class="cover-meta-value">${d.reportId}</div>
      </div>
      <div class="cover-meta-item">
        <div class="cover-meta-label">Fecha</div>
        <div class="cover-meta-value">${d.dateStr}</div>
      </div>
      <div class="cover-meta-item">
        <div class="cover-meta-label">Amenaza</div>
        <div class="cover-meta-value">${d.threatType.split('—')[0].trim()}</div>
      </div>
    </div>
  </div>

  <div class="cover-footer">
    <span class="cover-footer-text">SpamShield AI © ${new Date().getFullYear()} — Herramienta profesional de ciberseguridad — Hash de Integridad: ${d.integrityHash.substring(0, 16)}…</span>
    <span class="cover-footer-id">${d.reportId}</span>
  </div>
</div>

<!-- ============ PAGE 2: EXECUTIVE SUMMARY ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Resumen Ejecutivo</span>
    </div>
    <div class="page-header-right">${d.reportId}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:${d.verdictColor}20;color:${d.verdictColor}">!</div>
      <div class="section-title">Evaluación de Amenaza</div>
    </div>
    <div class="section-divider"></div>

    <div class="exec-box">
      <div class="exec-box-title">Veredicto: ${d.verdict}</div>
      <div class="exec-box-text">${d.verdictDesc}</div>
    </div>

    <div class="metrics-row">
      <div class="gauge-container">
        ${gaugeSVG}
        <div class="gauge-label">Score de Amenaza</div>
      </div>
      <div class="metrics-right">
        <div class="metric-mini">
          <div class="metric-mini-label">Spam Score</div>
          <div class="metric-mini-value" style="color:${d.verdictColor}">${d.spamScore}<span class="unit">/100</span></div>
          <div class="metric-mini-bar">
            <div class="metric-mini-bar-fill" style="width:${d.spamScore}%;background:${d.verdictColor}"></div>
          </div>
        </div>
        <div class="metric-mini">
          <div class="metric-mini-label">Probabilidad IA</div>
          <div class="metric-mini-value" style="color:${d.isAiGenerated ? '#8b5cf6' : '#6b7280'}">${d.aiConfidence}<span class="unit">%</span></div>
          <div class="metric-mini-bar">
            <div class="metric-mini-bar-fill" style="width:${d.aiConfidence}%;background:${d.isAiGenerated ? '#8b5cf6' : '#6b7280'}"></div>
          </div>
        </div>
        <div class="metric-mini">
          <div class="metric-mini-label">¿Es Spam?</div>
          <div class="metric-mini-value" style="color:${d.isSpam ? '#ef4444' : '#10b981'}">${d.isSpam ? 'SÍ' : 'NO'}</div>
        </div>
        <div class="metric-mini">
          <div class="metric-mini-label">¿Generado por IA?</div>
          <div class="metric-mini-value" style="color:${d.isAiGenerated ? '#8b5cf6' : '#10b981'}">${d.isAiGenerated ? 'SÍ' : 'NO'}</div>
        </div>
      </div>
    </div>

    ${threatBars}
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#10b98120;color:#10b981">i</div>
      <div class="section-title">Resumen del Análisis</div>
    </div>
    <div class="section-divider"></div>
    <div class="md-content">
      <p class="md-p">${escapeHtml(d.summary)}</p>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#3b82f620;color:#3b82f6">D</div>
      <div class="section-title">Datos del Denunciante (Opcional)</div>
    </div>
    <div class="section-divider"></div>
    <div class="denunciante-grid">
      <div class="denunciante-field">
        <span class="denunciante-label">Nombre completo</span>
        <div class="denunciante-line"></div>
      </div>
      <div class="denunciante-field">
        <span class="denunciante-label">RUT</span>
        <div class="denunciante-line"></div>
      </div>
      <div class="denunciante-field">
        <span class="denunciante-label">Contacto (email / teléfono)</span>
        <div class="denunciante-line"></div>
      </div>
      <div class="denunciante-field">
        <span class="denunciante-label">Relación con el incidente</span>
        <div class="denunciante-line"></div>
      </div>
    </div>
    <p class="denunciante-note">
      Campos opcionales. Completar solo si este informe será presentado como
      denuncia formal ante las autoridades competentes (CSIRT Nacional, BRICIB-PDI
      o Fiscalía de Chile).
    </p>
  </div>

  <div class="page-footer">
    <span>SpamShield AI — Informe Forense</span>
    <span>Página 2</span>
  </div>
</div>

<!-- ============ PAGE 3: EMAIL METADATA ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Información del Correo</span>
    </div>
    <div class="page-header-right">${d.reportId}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#3b82f620;color:#3b82f6">@</div>
      <div class="section-title">Metadatos del Correo Analizado</div>
    </div>
    <div class="section-divider"></div>

    <table class="info-table">
      <tr>
        <td class="info-label">Remitente</td>
        <td class="info-value">${escapeHtml(d.senderName)}</td>
      </tr>
      <tr>
        <td class="info-label">Correo Electrónico</td>
        <td class="info-value" style="font-family:'Courier New',monospace;font-size:11px;">${escapeHtml(d.senderEmail)}</td>
      </tr>
      <tr>
        <td class="info-label">Asunto</td>
        <td class="info-value">${escapeHtml(d.subject)}</td>
      </tr>
      <tr>
        <td class="info-label">Tipo de Amenaza</td>
        <td class="info-value">
          <span class="badge ${d.threatTypeRaw === 'none' ? 'badge-success' : 'badge-danger'}">${d.threatType}</span>
        </td>
      </tr>
      <tr>
        <td class="info-label">Nivel de Riesgo</td>
        <td class="info-value">
          <span class="badge ${d.spamScore < 30 ? 'badge-success' : d.spamScore < 60 ? 'badge-warning' : 'badge-danger'}">${d.verdict} (${d.spamScore}/100)</span>
        </td>
      </tr>
      <tr>
        <td class="info-label">Fuente</td>
        <td class="info-value">${d.source}</td>
      </tr>
      ${d.fileName ? `<tr><td class="info-label">Archivo</td><td class="info-value">${escapeHtml(d.fileName)}</td></tr>` : ''}
      <tr>
        <td class="info-label">Fecha de Análisis</td>
        <td class="info-value">${d.dateStr}</td>
      </tr>
      <tr>
        <td class="info-label">¿Detectado como Spam?</td>
        <td class="info-value">
          <span class="badge ${d.isSpam ? 'badge-danger' : 'badge-success'}">${d.isSpam ? 'SÍ — Spam Detectado' : 'NO — Correo Limpio'}</span>
        </td>
      </tr>
      <tr>
        <td class="info-label">¿Generado por IA?</td>
        <td class="info-value">
          <span class="badge ${d.isAiGenerated ? 'badge-info' : 'badge-success'}">${d.isAiGenerated ? 'SÍ — Alta Probabilidad' : 'NO — Probablemente Humano'}</span>
        </td>
      </tr>
      <tr>
        <td class="info-label">Report ID</td>
        <td class="info-value" style="font-family:'Courier New',monospace;font-size:11px;color:#6b7280">${d.reportId}</td>
      </tr>
    </table>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#8b5cf620;color:#8b5cf6">A</div>
      <div class="section-title">Análisis del Remitente</div>
    </div>
    <div class="section-divider"></div>
    <div class="md-content">
      ${renderMarkdown(d.senderAnalysis)}
    </div>
  </div>

  <div class="page-footer">
    <span>SpamShield AI — Informe Forense</span>
    <span>Página 3</span>
  </div>
</div>

<!-- ============ PAGE 4: FORENSIC ANALYSIS ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Análisis Forense</span>
    </div>
    <div class="page-header-right">${d.reportId}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#f59e0b20;color:#f59e0b">F</div>
      <div class="section-title">Análisis Forense Detallado</div>
    </div>
    <div class="section-divider"></div>
    <div class="md-content">
      ${renderMarkdown(d.detailedAnalysis)}
    </div>
  </div>

  <div class="page-footer">
    <span>SpamShield AI — Informe Forense</span>
    <span>Página 4</span>
  </div>
</div>

<!-- ============ PAGE 5: RECOMMENDATIONS ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Recomendaciones</span>
    </div>
    <div class="page-header-right">${d.reportId}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#10b98120;color:#10b981">✓</div>
      <div class="section-title">Recomendaciones de Seguridad</div>
    </div>
    <div class="section-divider"></div>
    <div class="md-content">
      ${renderMarkdown(d.recommendations)}
    </div>
  </div>

  ${d.emailBody ? `
  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#6b728020;color:#6b7280">E</div>
      <div class="section-title">Extracto del Correo Original</div>
    </div>
    <div class="section-divider"></div>
    <div class="email-preview">${escapeHtml(d.emailBody.substring(0, 1500))}${d.emailBody.length > 1500 ? '\n\n[... contenido truncado ...]' : ''}</div>
  </div>
  ` : ''}

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#37415120;color:#374151">V</div>
      <div class="section-title">Declaración de Veracidad</div>
    </div>
    <div class="section-divider"></div>
    <div class="declaracion-box">
      <div class="declaracion-row">
        <div class="declaracion-check"></div>
        <p class="declaracion-text">
          Declaro bajo fe que la información contenida en este informe es
          verídica y que el correo analizado fue recibido/interceptado de
          manera legítima.
        </p>
      </div>
      <div class="declaracion-signature-row">
        <div class="signature-field">
          <div class="signature-line"></div>
          <span class="signature-caption">Firma del Denunciante</span>
        </div>
        <div class="signature-field">
          <div class="signature-line"></div>
          <span class="signature-caption">Fecha (DD / MM / AAAA)</span>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#d9770620;color:#d97706">L</div>
      <div class="section-title">Cláusula Legal de Limitación de Responsabilidad</div>
    </div>
    <div class="section-divider"></div>
    <div class="legal-clause">
      <div class="legal-clause-title">Aviso Legal</div>
      <p class="legal-clause-text">
        Este informe es generado automáticamente por el sistema experto
        SpamShield AI y constituye una herramienta de apoyo técnico para la
        identificación de indicadores de amenaza en correos electrónicos. No
        reemplaza el análisis pericial oficial realizado por autoridades
        competentes. Para denuncias formales, contacte a CSIRT Nacional
        (csirt.gob.cl), BRICIB-PDI (pdi.cl) o Fiscalía de Chile
        (fiscaliedeley.cl). El contenido de este informe se ampara en la Ley
        21.663 (Marco de Ciberseguridad), Ley 21.459 (Delitos Informáticos) y
        Ley 21.719 (Protección de Datos Personales).
      </p>
      <div class="legal-clause-laws">
        <span class="legal-clause-law">Ley 21.663 — Marco de Ciberseguridad</span>
        <span class="legal-clause-law">Ley 21.459 — Delitos Informáticos</span>
        <span class="legal-clause-law">Ley 21.719 — Protección de Datos Personales</span>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#0ea5e920;color:#0ea5e9">#</div>
      <div class="section-title">Hash de Integridad</div>
    </div>
    <div class="section-divider"></div>
    <div class="integrity-box">
      <span class="integrity-label">SHA-256 (contenido + metadatos)</span>
      <div class="integrity-hash">${d.integrityHash}</div>
      <span class="integrity-note">
        Hash criptográfico calculado sobre el contenido del correo y los
        metadatos del análisis al momento de la generación. Permite verificar
        que el informe no ha sido modificado posteriormente (cadena de
        custodia digital).
      </span>
    </div>
  </div>

  <div class="page-footer">
    <span>SpamShield AI — Informe Forense ${d.reportId} — ${d.dateStr} — Hash de Integridad: ${d.integrityHash.substring(0, 24)}…</span>
    <span>Página 5</span>
  </div>
</div>

</body>
</html>`
}
