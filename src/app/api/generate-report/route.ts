import { NextRequest, NextResponse } from 'next/server'
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

    const threatLabels: Record<string, string> = {
      phishing: 'Phishing',
      voiceship: 'Estafa de Voz/CEO',
      spoofing: 'Spoofing',
      malware: 'Malware',
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

    const htmlReport = generateReportHTML({
      scanId: scan.id,
      verdict,
      verdictColor,
      verdictBg,
      spamScore: scan.spamScore ?? 0,
      aiConfidence: scan.aiConfidence ?? 0,
      isSpam: scan.isSpam,
      isAiGenerated: scan.isAiGenerated,
      threatType: threatLabels[scan.threatType || 'none'] || scan.threatType || 'Desconocido',
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
    })

    await db.emailScan.update({
      where: { id: scanId },
      data: { reportPath: `report-${scanId}.html` },
    })

    return new NextResponse(htmlReport, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="SpamShield-Informe-${scanId.substring(0, 8)}.html"`,
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

interface ReportData {
  scanId: string
  verdict: string
  verdictColor: string
  verdictBg: string
  spamScore: number
  aiConfidence: number
  isSpam: boolean
  isAiGenerated: boolean
  threatType: string
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
}

function generateReportHTML(d: ReportData): string {
  const simpleMarkdown = (md: string) => {
    return md
      .replace(/### (.*)/g, '<h3 style="font-size:15px;font-weight:700;color:#1f2937;margin:16px 0 8px;">$1</h3>')
      .replace(/## (.*)/g, '<h2 style="font-size:17px;font-weight:700;color:#111827;margin:20px 0 10px;border-bottom:1px solid #e5e7eb;padding-bottom:6px;">$1</h2>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/- (.*)/g, '<li style="margin-left:20px;margin-bottom:4px;color:#374151;">$1</li>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n/g, '<br>')
  }

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>SpamShield AI - Informe de Análisis</title>
<style>
  @page { size: A4; margin: 20mm; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; color: #1f2937; line-height: 1.6; background: #ffffff; }
  
  .cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    color: #ffffff; padding: 80px 60px; text-align: center;
    page-break-after: always; min-height: 100vh;
    display: flex; flex-direction: column; justify-content: center; align-items: center;
  }
  .cover-icon { font-size: 64px; margin-bottom: 24px; }
  .cover h1 { font-size: 36px; font-weight: 800; margin-bottom: 12px; letter-spacing: -0.5px; }
  .cover .subtitle { font-size: 18px; color: #94a3b8; margin-bottom: 40px; }
  .cover-meta { font-size: 13px; color: #64748b; margin-top: 40px; }
  .cover-meta span { margin: 0 12px; }
  
  .page { padding: 50px 60px; }
  
  .section { margin-bottom: 32px; }
  .section-title {
    font-size: 18px; font-weight: 700; color: #0f172a;
    padding-bottom: 8px; border-bottom: 2px solid #e2e8f0;
    margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px;
  }
  
  .verdict-banner {
    background: ${d.verdictBg}; border: 2px solid ${d.verdictColor};
    border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 32px;
  }
  .verdict-label { font-size: 12px; text-transform: uppercase; letter-spacing: 2px; color: #6b7280; margin-bottom: 8px; }
  .verdict-text { font-size: 32px; font-weight: 800; color: ${d.verdictColor}; letter-spacing: 3px; }
  
  .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }
  .metric-card {
    background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 10px; padding: 20px; text-align: center;
  }
  .metric-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #6b7280; margin-bottom: 8px; }
  .metric-value { font-size: 28px; font-weight: 800; color: #0f172a; }
  
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 24px; }
  .info-row { display: flex; padding: 8px 0; border-bottom: 1px solid #f1f5f9; }
  .info-label { font-size: 12px; color: #6b7280; font-weight: 600; width: 140px; flex-shrink: 0; }
  .info-value { font-size: 13px; color: #1f2937; word-break: break-all; }
  
  .analysis-content { font-size: 13.5px; color: #374151; line-height: 1.7; }
  
  .footer { text-align: center; padding: 24px; border-top: 1px solid #e2e8f0; margin-top: 40px; }
  .footer p { font-size: 11px; color: #9ca3af; }
  
  .page-break { page-break-before: always; }
  
  .print-btn {
    position: fixed; top: 20px; right: 20px; padding: 12px 24px;
    background: #0f172a; color: white; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 600; cursor: pointer; z-index: 1000;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
  }
  .print-btn:hover { background: #1e293b; }
  
  @media print { .print-btn { display: none; } }
</style>
</head>
<body>

<button class="print-btn" onclick="window.print()">Guardar como PDF</button>

<!-- COVER PAGE -->
<div class="cover">
  <div class="cover-icon">&#128737;</div>
  <h1>SpamShield AI</h1>
  <p class="subtitle">Informe de Análisis Forense de Correo Electrónico</p>
  <div style="background: ${d.verdictColor}; color: white; padding: 12px 48px; border-radius: 8px; font-size: 20px; font-weight: 700; letter-spacing: 3px;">${d.verdict}</div>
  <div class="cover-meta">
    <span>ID: ${d.scanId.substring(0, 12)}</span>
    <span>|</span>
    <span>${d.dateStr}</span>
  </div>
</div>

<!-- PAGE 2 -->
<div class="page">
  <div class="section">
    <div class="section-title">Resumen Ejecutivo</div>
    <div class="verdict-banner">
      <div class="verdict-label">Veredicto del Análisis</div>
      <div class="verdict-text">${d.verdict}</div>
    </div>
    <div class="analysis-content"><p>${escapeHtml(d.summary)}</p></div>
  </div>

  <div class="section">
    <div class="section-title">Métricas de Amenaza</div>
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">Puntuación de Spam</div>
        <div class="metric-value" style="color:${d.verdictColor}">${d.spamScore}%</div>
        <div style="margin-top:8px;height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${d.spamScore}%;background:${d.verdictColor};border-radius:4px;"></div>
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Probabilidad de Generación por IA</div>
        <div class="metric-value" style="color:${d.isAiGenerated ? '#8b5cf6' : '#6b7280'}">${d.aiConfidence}%</div>
        <div style="margin-top:8px;height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${d.aiConfidence}%;background:${d.isAiGenerated ? '#8b5cf6' : '#6b7280'};border-radius:4px;"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Información del Correo Analizado</div>
    <div class="info-grid">
      <div class="info-row"><div class="info-label">Remitente</div><div class="info-value">${escapeHtml(d.senderName)}</div></div>
      <div class="info-row"><div class="info-label">Correo</div><div class="info-value">${escapeHtml(d.senderEmail)}</div></div>
      <div class="info-row"><div class="info-label">Asunto</div><div class="info-value">${escapeHtml(d.subject)}</div></div>
      <div class="info-row"><div class="info-label">Tipo de Amenaza</div><div class="info-value" style="font-weight:600;color:${d.verdictColor}">${d.threatType}</div></div>
      <div class="info-row"><div class="info-label">Fuente</div><div class="info-value">${d.source}</div></div>
      ${d.fileName ? `<div class="info-row"><div class="info-label">Archivo</div><div class="info-value">${escapeHtml(d.fileName)}</div></div>` : ''}
      <div class="info-row"><div class="info-label">Fecha de Análisis</div><div class="info-value">${d.dateStr}</div></div>
      <div class="info-row"><div class="info-label">¿Es Spam?</div><div class="info-value" style="font-weight:600;color:${d.isSpam ? '#ef4444' : '#10b981'}">${d.isSpam ? 'SÍ — Detectado' : 'NO — Limpio'}</div></div>
      <div class="info-row"><div class="info-label">¿Generado por IA?</div><div class="info-value" style="font-weight:600;color:${d.isAiGenerated ? '#8b5cf6' : '#10b981'}">${d.isAiGenerated ? 'SÍ — Alta probabilidad' : 'NO — Probablemente humano'}</div></div>
    </div>
  </div>
</div>

<!-- PAGE 3 -->
<div class="page page-break">
  <div class="section">
    <div class="section-title">Análisis del Remitente</div>
    <div class="analysis-content"><p>${simpleMarkdown(d.senderAnalysis)}</p></div>
  </div>

  <div class="section">
    <div class="section-title">Análisis Forense Detallado</div>
    <div class="analysis-content"><p>${simpleMarkdown(d.detailedAnalysis)}</p></div>
  </div>

  <div class="section">
    <div class="section-title">Recomendaciones de Seguridad</div>
    <div class="analysis-content"><p>${simpleMarkdown(d.recommendations)}</p></div>
  </div>

  <div class="footer">
    <p>Informe generado por <strong>SpamShield AI</strong> — Análisis Forense de Correo Electrónico</p>
    <p style="margin-top:4px;">Este informe es generado automáticamente y debe ser considerado como una herramienta de apoyo.</p>
  </div>
</div>

</body>
</html>`
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
