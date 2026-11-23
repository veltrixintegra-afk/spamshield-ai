import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'
import { db } from '@/lib/db'

/* ============================================================
   OFFICIAL COMPLAINT REPORT GENERATOR
   SpamShield AI — Documento Oficial de Denuncia
   ============================================================ */

interface DenuncianteInput {
  nombre: string
  rut: string
  nacionalidad: string
  domicilio: string
  telefono: string
  email: string
  relacion: string
}

type AutoridadKey = 'pdi' | 'carabineros' | 'anci' | 'fiscalia' | 'todas'

interface OfficialReportInput {
  scanId: string
  denunciante: DenuncianteInput
  autoridad: AutoridadKey
  firmaDigital: string
  fecha: string
  aceptaDeclaracion: boolean
}

const AUTHORITIES: Record<
  AutoridadKey,
  { name: string; short: string; desc: string; url: string; address: string }
> = {
  pdi: {
    name: 'PDI — BRICIB (Brigada de Delitos Cibernéticos)',
    short: 'PDI / BRICIB',
    desc: 'Brigada de Investigaciones de Delitos Cibernéticos. Competente en cibercrimen, phishing, fraude electrónico y suplantación de identidad en medios digitales.',
    url: 'https://www.pdi.cl',
    address: 'Av. Pedro Montt 2354, Santiago — Brigada de Delitos Cibernéticos (BRICIB)',
  },
  carabineros: {
    name: 'Carabineros de Chile',
    short: 'Carabineros',
    desc: 'Policía de Orden y Seguridad Pública. Recibe denuncias por delitos en general, incluida la comisión inmediata de delitos informáticos y situaciones de peligro inminente.',
    url: 'https://www.carabineros.cl',
    address: 'Unidad policial (comisaría) más cercana a su domicilio. Para emergencias marque 133.',
  },
  anci: {
    name: 'ANCI — Agencia Nacional de Ciberseguridad',
    short: 'ANCI / CSIRT Nacional',
    desc: 'Agencia Nacional de Ciberseguridad (transitoriamente vía CSIRT Nacional). Recibe reportes de incidentes de ciberseguridad y coordina la respuesta nacional.',
    url: 'https://csirt.gob.cl',
    address: 'CSIRT Nacional — https://csirt.gob.cl — Reporte de incidentes en línea.',
  },
  fiscalia: {
    name: 'Fiscalía — Ministerio Público',
    short: 'Fiscalía de Chile',
    desc: 'Ministerio Público. Inicia la investigación formal de delitos informáticos conforme a la Ley 21.459 (Art. 211B phishing y delitos conexos).',
    url: 'https://www.fiscaliedeley.cl',
    address: 'Fiscalía Local con competencia territorial sobre el domicilio del denunciante.',
  },
  todas: {
    name: 'Denuncia Universal — Todas las Autoridades Competentes',
    short: 'Denuncia Universal',
    desc: 'Documento universal aplicable para presentación simultánea ante PDI/BRICIB, Carabineros de Chile, ANCI/CSIRT Nacional y Fiscalía de Chile.',
    url: 'https://csirt.gob.cl',
    address: 'Múltiples destinos. Ver listado de autoridades competentes en página 7.',
  },
}

const RELACION_LABELS: Record<string, string> = {
  Victima: 'Víctima del incidente',
  Testigo: 'Testigo presencial o con conocimiento del hecho',
  Representante: 'Representante legal de la víctima',
  Tercero: 'Tercero con legítimo interés en la denuncia',
}

const SWORN_DECLARATION_POINTS = [
  'La información contenida en este informe es verídica y corresponde a un correo electrónico que recibí o tuve acceso legítimo.',
  'El correo electrónico analizado no fue modificado, alterado ni fabricado.',
  'Autorizo el uso de este informe como documento de respaldo para la denuncia correspondiente ante la autoridad destinataria.',
  'Asumo plena responsabilidad civil y penal por la veracidad del contenido denunciado.',
  'Entiendo que SpamShield AI es una herramienta de apoyo técnico y no constituye prueba pericial oficial.',
  'El análisis fue realizado mediante un sistema experto automatizado que evalúa indicadores técnicos de amenaza.',
  'Autorizo a las autoridades a verificar la autenticidad de este informe mediante el hash de integridad incluido.',
]

const APPLICABLE_LAWS = [
  {
    code: 'Ley 21.663',
    name: 'Marco de Ciberseguridad',
    desc: 'Establece el marco general de ciberseguridad para instituciones del Estado y operadores de importancia vital. Crea la Agencia Nacional de Ciberseguridad (ANCI) y el CSIRT Nacional.',
  },
  {
    code: 'Ley 21.459',
    name: 'Delitos Informáticos',
    desc: 'Tipifica delitos contra la integridad de los datos y sistemas, acceso ilícito, ataque a la integridad de sistemas, suplantación de identidad y phishing. Artículo 211B: suplantación de identidad mediante medios digitales con ánimo de lucro.',
  },
  {
    code: 'Ley 21.719',
    name: 'Protección de Datos Personales',
    desc: 'Regula el tratamiento de datos personales y garantiza los derechos ARCO (Acceso, Rectificación, Cancelación, Oposición) de los titulares de datos en Chile.',
  },
  {
    code: 'Art. 210 Código Penal',
    name: 'Falsa Declaración ante Autoridad',
    desc: 'Sanciona con penas de presidio al que ante autoridad pública diere en asunto de carácter civil una declaración falsa relativa a hechos que deban servir de fundamento o prueba en un juicio.',
  },
  {
    code: 'Art. 211B Código Penal',
    name: 'Suplantación de Identidad y Phishing',
    desc: 'Tipifica la suplantación de identidad por medios digitales, con penas agravadas cuando el agente actúa con ánimo de lucro o para obtener ventajas patrimoniales indebidas (phishing).',
  },
]

export async function POST(request: NextRequest) {
  try {
    const body: OfficialReportInput = await request.json()

    // ── Validación de campos requeridos ──
    if (!body.scanId) {
      return NextResponse.json(
        { error: 'ID de análisis (scanId) requerido' },
        { status: 400 }
      )
    }

    const d = body.denunciante
    if (
      !d?.nombre ||
      !d?.rut ||
      !d?.domicilio ||
      !d?.telefono ||
      !d?.email
    ) {
      return NextResponse.json(
        { error: 'Faltan datos obligatorios del denunciante' },
        { status: 400 }
      )
    }

    if (!body.firmaDigital || body.firmaDigital.trim().length < 4) {
      return NextResponse.json(
        { error: 'La firma digital (nombre completo) es obligatoria' },
        { status: 400 }
      )
    }

    if (body.aceptaDeclaracion !== true) {
      return NextResponse.json(
        { error: 'Debe aceptar la declaración jurada de responsabilidad' },
        { status: 400 }
      )
    }

    if (!AUTHORITIES[body.autoridad]) {
      return NextResponse.json(
        { error: 'Autoridad destinataria inválida' },
        { status: 400 }
      )
    }

    const scan = await db.emailScan.findUnique({
      where: { id: body.scanId },
    })

    if (!scan) {
      return NextResponse.json(
        { error: 'Análisis no encontrado en la base de datos' },
        { status: 404 }
      )
    }

    let analysisData: Record<string, unknown> = {}
    try {
      if (scan.analysisJson) {
        analysisData = JSON.parse(scan.analysisJson)
      }
    } catch {
      analysisData = {}
    }

    // ── Generar Número de Caso Oficial: SSA-YYYY-NNNNNN ──
    const year = new Date().getFullYear()
    const randomDigits = String(
      Math.floor(Math.random() * 1000000)
    ).padStart(6, '0')
    const caseNumber = `SSA-${year}-${randomDigits}`

    // ── Veredicto y métricas ──
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

    const declarationDate = new Date(body.fecha).toLocaleDateString('es-CL', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })

    const authority = AUTHORITIES[body.autoridad]

    // ── Hash de Integridad SHA-256 ──
    // Calculado sobre scanId + datos del denunciante + fecha + análisis
    const integrityPayload = JSON.stringify({
      scanId: scan.id,
      denunciante: {
        nombre: d.nombre,
        rut: d.rut,
        domicilio: d.domicilio,
        email: d.email,
        telefono: d.telefono,
      },
      autoridad: body.autoridad,
      firmaDigital: body.firmaDigital,
      fecha: body.fecha,
      analysis: {
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
      },
    })
    const integrityHash = crypto
      .createHash('sha256')
      .update(integrityPayload, 'utf8')
      .digest('hex')

    const htmlReport = generateOfficialReportHTML({
      caseNumber,
      scanId: scan.id,
      authority,
      autoridadKey: body.autoridad,
      denunciante: d,
      firmaDigital: body.firmaDigital,
      fecha: body.fecha,
      declarationDate,
      verdict,
      verdictColor,
      verdictBg,
      verdictDesc,
      spamScore: scan.spamScore ?? 0,
      aiConfidence: scan.aiConfidence ?? 0,
      isSpam: scan.isSpam,
      isAiGenerated: scan.isAiGenerated,
      threatType:
        threatLabels[scan.threatType || 'none'] || scan.threatType || 'Desconocido',
      threatTypeRaw: scan.threatType || 'none',
      source: sourceLabels[scan.source] || scan.source,
      senderEmail: scan.senderEmail || 'No identificado',
      senderName: scan.senderName || scan.senderEmail || 'No identificado',
      subject: scan.subject || 'Sin asunto',
      fileName: scan.fileName,
      dateStr,
      senderAnalysis:
        (analysisData.senderAnalysis as string) || 'No disponible',
      summary: (analysisData.summary as string) || 'No disponible',
      detailedAnalysis:
        (analysisData.detailedAnalysis as string) || 'No disponible',
      recommendations:
        (analysisData.recommendations as string) || 'No disponibles',
      emailBody: scan.emailBody,
      integrityHash,
    })

    return new NextResponse(htmlReport, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="SpamShield-Denuncia-${caseNumber}.html"`,
      },
    })
  } catch (error) {
    console.error('Error generating official report:', error)
    return NextResponse.json(
      { error: 'Error al generar el informe oficial de denuncia' },
      { status: 500 }
    )
  }
}

/* ============================================================
   HELPERS
   ============================================================ */

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
  if (score === null)
    return 'No se pudo determinar el nivel de amenaza a partir de los datos analizados.'
  if (score < 30)
    return 'El correo electrónico no presenta indicadores significativos de amenaza. El contenido parece legítimo y seguro.'
  if (score < 60)
    return 'El correo presenta algunos indicadores sospechosos. Se recomienda verificar el remitente antes de interactuar con el contenido.'
  if (score < 80)
    return 'El correo presenta múltiples indicadores de amenaza. Se recomienda no interactuar con el contenido y eliminar el correo.'
  return 'El correo presenta indicadores críticos de amenaza. No interactúe con ningún enlace o adjunto. Elimine inmediatamente y reporte a las autoridades competentes.'
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/* ── Markdown renderer ── */
function renderMarkdown(md: string): string {
  let html = escapeHtml(md)
  html = html.replace(/^### (.+)$/gm, '<h3 class="md-h3">$1</h3>')
  html = html.replace(/^## (.+)$/gm, '<h2 class="md-h2">$1</h2>')
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>')
  html = html.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>')
  html = html.replace(/(?:^(- .+(?:\n|$))+)/gm, (match) => {
    const items = match.trim().split('\n').map((line) => {
      const content = line.replace(/^- /, '')
      if (line.startsWith('  - ')) {
        return `<li class="md-subitem">${line.replace(/^\s+- /, '')}</li>`
      }
      return `<li class="md-item">${content}</li>`
    })
    return `<ul class="md-list">${items.join('')}</ul>`
  })
  html = html.replace(/\n\n/g, '</p><p class="md-p">')
  html = html.replace(/\n/g, '<br>')
  if (!html.startsWith('<')) {
    html = `<p class="md-p">${html}</p>`
  }
  return html
}

/* ── SVG Gauge ── */
function generateGaugeSVG(score: number, color: string): string {
  const radius = 80
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  return `
  <svg width="200" height="200" viewBox="0 0 200 200" class="gauge-svg">
    <defs>
      <linearGradient id="gaugeGradOff" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.6"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="1"/>
      </linearGradient>
      <filter id="gaugeShadowOff">
        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.15"/>
      </filter>
    </defs>
    <circle cx="100" cy="100" r="${radius}" fill="none" stroke="#e5e7eb" stroke-width="12"/>
    <circle cx="100" cy="100" r="${radius}" fill="none" stroke="url(#gaugeGradOff)" stroke-width="12"
      stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
      transform="rotate(-90 100 100)" filter="url(#gaugeShadowOff)"/>
    <text x="100" y="95" text-anchor="middle" font-size="42" font-weight="800" fill="${color}" font-family="Arial">${score}</text>
    <text x="100" y="115" text-anchor="middle" font-size="13" fill="#9ca3af" font-family="Arial">/ 100</text>
  </svg>`
}

/* ── Threat category bars ── */
function generateThreatBars(
  spamScore: number,
  aiConfidence: number,
  threatTypeRaw: string
): string {
  const categories = [
    { label: 'Spam General', score: spamScore, color: '#ef4444', icon: 'S' },
    {
      label: 'Phishing',
      score: threatTypeRaw === 'phishing' ? spamScore : Math.round(spamScore * 0.3),
      color: '#f97316',
      icon: 'P',
    },
    {
      label: 'Voiceship/CEO',
      score:
        threatTypeRaw === 'voiceship' ? spamScore : Math.round(spamScore * 0.2),
      color: '#8b5cf6',
      icon: 'V',
    },
    { label: 'Contenido IA', score: aiConfidence, color: '#6366f1', icon: 'AI' },
  ]

  return `
  <div class="threat-bars">
    ${categories
      .map(
        (cat) => `
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
      </div>`
      )
      .join('')}
  </div>`
}

/* ============================================================
   OFFICIAL REPORT HTML GENERATOR (7 pages)
   ============================================================ */
interface OfficialReportData {
  caseNumber: string
  scanId: string
  authority: { name: string; short: string; desc: string; url: string; address: string }
  autoridadKey: string
  denunciante: DenuncianteInput
  firmaDigital: string
  fecha: string
  declarationDate: string
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

function generateOfficialReportHTML(d: OfficialReportData): string {
  const gaugeSVG = generateGaugeSVG(d.spamScore, d.verdictColor)
  const threatBars = generateThreatBars(
    d.spamScore,
    d.aiConfidence,
    d.threatTypeRaw
  )

  const declarationPointsHtml = SWORN_DECLARATION_POINTS.map(
    (point, idx) =>
      `<li class="decl-point"><span class="decl-num">${idx + 1}.</span><span class="decl-text">${point}</span></li>`
  ).join('')

  const lawsHtml = APPLICABLE_LAWS.map(
    (law) => `
    <div class="law-item">
      <div class="law-code">${law.code}</div>
      <div class="law-body">
        <div class="law-name">${law.name}</div>
        <div class="law-desc">${law.desc}</div>
      </div>
    </div>`
  ).join('')

  const emailPreviewText = d.emailBody
    ? escapeHtml(
        d.emailBody.substring(0, 1800) +
          (d.emailBody.length > 1800 ? '\n\n[... contenido truncado para el extracto ...]' : '')
      )
    : 'No se dispone del contenido del correo electrónico.'

  const custodySteps = [
    {
      n: '1',
      t: 'Recepción del correo electrónico',
      d: 'El correo electrónico analizado fue recibido por el denunciante o accedido legítimamente por éste, conforme a la declaración jurada incluida en este documento (página 3).',
    },
    {
      n: '2',
      t: 'Ingreso al sistema SpamShield AI',
      d: `El contenido del correo fue ingresado al sistema experto SpamShield AI el ${d.dateStr}, asignándosele el identificador interno de análisis ${d.scanId.substring(0, 12).toUpperCase()}.`,
    },
    {
      n: '3',
      t: 'Análisis automatizado',
      d: 'El sistema experto procesó el correo aplicando detectores de spam, phishing, voiceship/CEO fraud, spoofing, malware, ingeniería social y detección de contenido generado por inteligencia artificial. Cada detector evalúa indicadores técnicos objetivos.',
    },
    {
      n: '4',
      t: 'Cálculo de métricas',
      d: `Se calculó el Spam Score en ${d.spamScore}/100 (veredicto: ${d.verdict}), probabilidad de generación por IA en ${d.aiConfidence}% y tipo de amenaza principal: ${d.threatType}.`,
    },
    {
      n: '5',
      t: 'Generación del informe oficial',
      d: `Se generó el presente informe oficial con número de caso ${d.caseNumber}, incluyendo el hash de integridad SHA-256 que vincula criptográficamente los datos del denunciante, el análisis y la fecha de emisión.`,
    },
    {
      n: '6',
      t: 'Custodia del denunciante',
      d: 'El documento final es entregado al denunciante, quien asume la responsabilidad de su contenido conforme a la declaración jurada firmada. La verificación de autenticidad puede efectuarse mediante el número de caso y el hash SHA-256 incluidos.',
    },
  ]

  const custodyHtml = custodySteps
    .map(
      (s) => `
    <div class="custody-step">
      <div class="custody-num">${s.n}</div>
      <div class="custody-body">
        <div class="custody-title">${s.t}</div>
        <div class="custody-desc">${s.d}</div>
      </div>
    </div>`
    )
    .join('')

  const fullDeclarationText = `
    Yo, ${escapeHtml(d.denunciante.nombre)}, RUT ${escapeHtml(
    d.denunciante.rut
  )}, bajo declaración solemne y con conocimiento de las penas establecidas en el Artículo 210 del Código Penal de Chile por falsas declaraciones ante autoridad, declaro que:
    ${SWORN_DECLARATION_POINTS.map((p, i) => `(${i + 1}) ${p}`).join(' ')}
    Base Legal: Ley 21.663 (Marco de Ciberseguridad), Ley 21.459 (Delitos Informáticos - Art. 211B phishing), Ley 21.719 (Protección de Datos Personales), Art. 210 Código Penal (falsa declaración).
  `
    .replace(/\s+/g, ' ')
    .trim()

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>SpamShield AI — Informe Oficial de Denuncia ${d.caseNumber}</title>
<style>
  @page { size: A4; margin: 0; }
  @page :first { margin: 0; }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    color: #1f2937;
    line-height: 1.6;
    background: #ffffff;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  /* ── PRINT BAR ── */
  .print-bar {
    position: fixed;
    top: 0; left: 0; right: 0;
    background: #064e3b;
    color: white;
    padding: 12px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    z-index: 10000;
    box-shadow: 0 2px 8px rgba(0,0,0,0.25);
  }
  .print-bar-text {
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .print-bar-text .shield-icon { color: #34d399; }
  .print-bar-text .case-num {
    font-family: 'Courier New', monospace;
    font-size: 12px;
    background: rgba(52,211,153,0.15);
    border: 1px solid rgba(52,211,153,0.4);
    padding: 2px 8px;
    border-radius: 4px;
    color: #6ee7b7;
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
    border: 1px solid rgba(255,255,255,0.25);
    margin-left: 8px;
  }
  .print-btn-close:hover { background: rgba(255,255,255,0.1); }

  @media print {
    .print-bar { display: none; }
    .page { min-height: auto; padding-top: 30mm; }
  }

  /* ── COVER PAGE ── */
  .cover {
    background: linear-gradient(135deg, #022c22 0%, #064e3b 40%, #0a0f1e 100%);
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
    width: 450px; height: 450px;
    background: radial-gradient(circle, rgba(16,185,129,0.18) 0%, transparent 70%);
    border-radius: 50%;
  }
  .cover::after {
    content: '';
    position: absolute;
    bottom: -150px; left: -150px;
    width: 550px; height: 550px;
    background: radial-gradient(circle, rgba(52,211,153,0.10) 0%, transparent 70%);
    border-radius: 50%;
  }

  .cover-header {
    padding: 38px 50px 0;
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
    width: 42px; height: 42px;
    background: rgba(16,185,129,0.18);
    border: 1px solid rgba(16,185,129,0.4);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
  }
  .cover-logo-icon svg { width: 24px; height: 24px; }
  .cover-logo-text {
    font-size: 19px; font-weight: 700; letter-spacing: -0.3px;
  }
  .cover-logo-text span { color: #10b981; }

  .cover-classification {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: #fca5a5; border: 1px solid rgba(252,165,165,0.4);
    padding: 5px 14px; border-radius: 4px;
    background: rgba(239,68,68,0.08);
    font-weight: 600;
  }

  .cover-body {
    padding: 50px 50px 30px;
    position: relative;
    z-index: 2;
  }

  .cover-eyebrow {
    font-size: 13px; letter-spacing: 4px; text-transform: uppercase;
    color: #34d399; margin-bottom: 14px; font-weight: 600;
  }
  .cover-h1 {
    font-size: 40px; font-weight: 800; letter-spacing: -1px;
    line-height: 1.12; margin-bottom: 18px;
  }
  .cover-subtitle {
    font-size: 14px; color: #9ca3af; max-width: 540px; line-height: 1.7;
  }

  .cover-case-box {
    margin: 36px 0 28px;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(52,211,153,0.3);
    border-radius: 12px;
    padding: 22px 28px;
    display: inline-block;
  }
  .cover-case-label {
    font-size: 10px; letter-spacing: 2.5px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 6px; font-weight: 600;
  }
  .cover-case-number {
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 36px; font-weight: 800; color: #34d399;
    letter-spacing: 3px;
  }
  .cover-case-sub {
    font-size: 11px; color: #94a3b8; margin-top: 6px;
  }

  .cover-authority-box {
    margin: 20px 0;
    max-width: 580px;
  }
  .cover-authority-label {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 6px; font-weight: 600;
  }
  .cover-authority-name {
    font-size: 17px; color: #e2e8f0; font-weight: 600;
  }

  .cover-meta-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 24px;
    margin-top: 30px;
    max-width: 600px;
  }
  .cover-meta-item {
    border-left: 2px solid rgba(52,211,153,0.4);
    padding-left: 12px;
  }
  .cover-meta-label {
    font-size: 9px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 4px; font-weight: 600;
  }
  .cover-meta-value {
    font-size: 13px; color: #e2e8f0; font-weight: 500;
  }

  .cover-hash-row {
    margin-top: 30px;
    max-width: 600px;
  }
  .cover-hash-label {
    font-size: 9px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 4px; font-weight: 600;
  }
  .cover-hash-value {
    font-family: 'Courier New', monospace;
    font-size: 11px; color: #94a3b8;
    word-break: break-all;
  }

  .cover-footer {
    position: absolute;
    bottom: 28px; left: 50px; right: 50px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px solid rgba(148,163,184,0.15);
    padding-top: 14px;
    z-index: 2;
  }
  .cover-footer-text { font-size: 10px; color: #6b7280; }
  .cover-footer-id {
    font-size: 11px; color: #94a3b8; font-family: 'Courier New', monospace;
  }

  /* ── CONTENT PAGES ── */
  .page {
    padding: 38px 50px 36px;
    min-height: 297mm;
    position: relative;
    page-break-after: always;
  }
  .page:last-child { page-break-after: auto; }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 10px;
    border-bottom: 2px solid #064e3b;
    margin-bottom: 22px;
  }
  .page-header-left {
    display: flex; align-items: center; gap: 8px;
    font-size: 11px; color: #064e3b; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1.2px;
  }
  .page-header-left .shield-dot {
    width: 9px; height: 9px; border-radius: 50%; background: #10b981;
  }
  .page-header-right {
    font-size: 10px; color: #6b7280; font-family: 'Courier New', monospace;
    font-weight: 600;
  }

  .page-footer {
    position: absolute;
    bottom: 16px; left: 50px; right: 50px;
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    align-items: center;
    border-top: 1px solid #e5e7eb;
    padding-top: 8px;
    font-size: 9px; color: #9ca3af;
  }
  .page-footer .pf-left {
    font-family: 'Courier New', monospace;
    color: #064e3b;
    font-weight: 600;
  }
  .page-footer .pf-center { text-align: center; }
  .page-footer .pf-right { text-align: right; color: #6b7280; }

  /* ── SECTIONS ── */
  .section { margin-bottom: 24px; }
  .section-header {
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 12px;
  }
  .section-icon {
    width: 26px; height: 26px; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
  }
  .section-title {
    font-size: 14px; font-weight: 700; color: #022c22;
    text-transform: uppercase; letter-spacing: 0.6px;
  }
  .section-divider {
    height: 2px; background: linear-gradient(90deg, #10b981 0%, transparent 100%);
    margin-bottom: 14px;
  }

  /* ── DATA TABLE ── */
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
    width: 180px;
    color: #6b7280;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background: #f0fdf4;
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
  .badge-emerald { background: #ecfdf5; color: #047857; border: 1px solid #6ee7b7; }

  /* ── DECLARATION PAGE ── */
  .decl-box {
    background: #ffffff;
    border: 2px solid #064e3b;
    border-radius: 10px;
    padding: 26px 32px;
    margin-top: 4px;
  }
  .decl-title {
    font-size: 15px; font-weight: 800; color: #022c22;
    text-transform: uppercase; letter-spacing: 1px;
    text-align: center;
    padding-bottom: 12px;
    border-bottom: 2px solid #064e3b;
    margin-bottom: 18px;
  }
  .decl-preamble {
    font-size: 12.5px; color: #1f2937; line-height: 1.85;
    margin-bottom: 16px;
    text-align: justify;
  }
  .decl-list {
    list-style: none;
    padding: 0;
    margin-bottom: 16px;
  }
  .decl-point {
    display: flex;
    gap: 10px;
    margin-bottom: 10px;
    font-size: 12px;
    color: #1f2937;
    line-height: 1.7;
  }
  .decl-num {
    font-weight: 700;
    color: #047857;
    flex-shrink: 0;
    min-width: 22px;
  }
  .decl-text { flex: 1; text-align: justify; }

  .decl-base-legal {
    background: #fffbeb;
    border-left: 4px solid #d97706;
    border-radius: 6px;
    padding: 12px 16px;
    font-size: 11.5px;
    color: #4b3613;
    line-height: 1.7;
    margin-top: 14px;
  }
  .decl-base-legal strong { color: #92400e; }

  .signature-block {
    margin-top: 28px;
    text-align: center;
  }
  .signature-rendered {
    font-family: 'Brush Script MT', 'Lucida Handwriting', 'Segoe Script', cursive;
    font-size: 28px;
    color: #022c22;
    font-style: italic;
    padding: 10px 0 6px;
    border-bottom: 1px solid #022c22;
    margin: 0 auto;
    max-width: 380px;
    min-height: 30px;
    letter-spacing: 1px;
  }
  .signature-caption {
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #6b7280; font-weight: 600; margin-top: 6px;
  }
  .signature-date {
    font-size: 12px; color: #1f2937; margin-top: 12px; font-weight: 500;
  }
  .signature-note {
    margin-top: 18px;
    font-size: 10px; color: #6b7280; font-style: italic;
    text-align: center;
    line-height: 1.6;
  }

  /* ── EXEC BOX / METRICS ── */
  .exec-box {
    background: linear-gradient(135deg, ${d.verdictBg} 0%, #ffffff 100%);
    border: 1px solid ${d.verdictColor}30;
    border-left: 4px solid ${d.verdictColor};
    border-radius: 10px;
    padding: 22px;
    margin-bottom: 18px;
  }
  .exec-box-title {
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
    color: #6b7280; margin-bottom: 8px; font-weight: 600;
  }
  .exec-box-text {
    font-size: 13px; color: #374151; line-height: 1.7;
  }

  .metrics-row {
    display: flex;
    gap: 30px;
    align-items: center;
    margin-bottom: 22px;
  }
  .gauge-container { flex-shrink: 0; text-align: center; }
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
  .metric-mini-bar-fill { height: 100%; border-radius: 2px; }

  .threat-bars { display: flex; flex-direction: column; gap: 10px; }
  .threat-bar-row { display: flex; align-items: center; gap: 12px; }
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
  .threat-bar-fill { height: 100%; border-radius: 3px; }

  /* ── MARKDOWN CONTENT ── */
  .md-content {
    font-size: 12.5px;
    color: #374151;
    line-height: 1.75;
  }
  .md-h2 {
    font-size: 14px; font-weight: 700; color: #111827;
    margin: 16px 0 10px; padding-bottom: 6px;
    border-bottom: 1px solid #e5e7eb;
  }
  .md-h3 {
    font-size: 13px; font-weight: 700; color: #1f2937;
    margin: 12px 0 8px;
  }
  .md-p { margin-bottom: 10px; }
  .md-list { list-style: none; padding-left: 0; margin-bottom: 12px; }
  .md-item {
    padding-left: 20px; position: relative; margin-bottom: 6px;
  }
  .md-item::before {
    content: ''; position: absolute;
    left: 4px; top: 9px;
    width: 6px; height: 6px; border-radius: 50%;
    background: #10b981;
  }
  .md-subitem {
    padding-left: 40px; position: relative; margin-bottom: 4px;
    font-size: 11.5px; color: #6b7280;
  }
  .md-subitem::before {
    content: '\\2192'; position: absolute; left: 24px; color: #9ca3af;
  }
  .md-code {
    background: #f3f4f6; padding: 1px 6px; border-radius: 3px;
    font-size: 11px; font-family: 'Courier New', monospace; color: #dc2626;
  }
  .md-content strong { color: #111827; }
  .md-content em { color: #6b7280; }

  /* ── EMAIL PREVIEW ── */
  .email-preview {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
    max-height: 320px;
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

  /* ── LEGAL FRAMEWORK ── */
  .law-item {
    display: flex;
    gap: 14px;
    padding: 12px 14px;
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 8px;
    margin-bottom: 10px;
  }
  .law-code {
    flex-shrink: 0;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    font-weight: 700;
    color: #047857;
    background: #ffffff;
    border: 1px solid #6ee7b7;
    padding: 6px 10px;
    border-radius: 6px;
    text-align: center;
    min-width: 110px;
  }
  .law-body { flex: 1; }
  .law-name {
    font-size: 12px; font-weight: 700; color: #022c22;
    margin-bottom: 4px;
  }
  .law-desc {
    font-size: 11px; color: #374151; line-height: 1.65;
  }

  /* ── AUTHORITIES ── */
  .auth-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 10px;
  }
  .auth-card {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 12px 16px;
    background: #ffffff;
  }
  .auth-card.active {
    border: 2px solid #10b981;
    background: #f0fdf4;
  }
  .auth-card-name {
    font-size: 13px; font-weight: 700; color: #022c22;
    margin-bottom: 4px;
  }
  .auth-card-desc {
    font-size: 11px; color: #6b7280; line-height: 1.6;
    margin-bottom: 6px;
  }
  .auth-card-contact {
    font-size: 11px; color: #047857;
    font-family: 'Courier New', monospace;
  }
  .auth-card-address {
    font-size: 10.5px; color: #374151; margin-top: 4px;
  }

  /* ── CHAIN OF CUSTODY ── */
  .custody-step {
    display: flex;
    gap: 14px;
    margin-bottom: 12px;
    padding-bottom: 12px;
    border-bottom: 1px dashed #e5e7eb;
  }
  .custody-step:last-child {
    border-bottom: none; margin-bottom: 0; padding-bottom: 0;
  }
  .custody-num {
    flex-shrink: 0;
    width: 32px; height: 32px;
    border-radius: 50%;
    background: #10b981;
    color: white;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 700;
  }
  .custody-body { flex: 1; }
  .custody-title {
    font-size: 12.5px; font-weight: 700; color: #022c22;
    margin-bottom: 3px;
  }
  .custody-desc {
    font-size: 11px; color: #374151; line-height: 1.65;
  }

  /* ── INTEGRITY HASH ── */
  .integrity-box {
    display: flex; flex-direction: column; gap: 6px;
    margin-top: 8px;
  }
  .integrity-label {
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: #6b7280; font-weight: 600;
  }
  .integrity-hash {
    font-family: 'Courier New', monospace;
    font-size: 10.5px;
    color: #022c22;
    word-break: break-all;
    background: #f0fdf4;
    padding: 12px 14px;
    border-radius: 6px;
    border: 1px solid #6ee7b7;
    font-weight: 600;
  }
  .integrity-note {
    font-size: 10px; color: #6b7280; font-style: italic;
    line-height: 1.6;
  }
  .verification-box {
    background: #ecfdf5;
    border: 1px dashed #10b981;
    border-radius: 8px;
    padding: 14px 18px;
    margin-top: 14px;
  }
  .verification-title {
    font-size: 11px; font-weight: 700; color: #047857;
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 6px;
  }
  .verification-text {
    font-size: 11.5px; color: #064e3b; line-height: 1.7;
  }

  /* ── RESPONSIBILITY CLAUSE (final) ── */
  .resp-clause {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 18px 22px;
    font-size: 11px;
    color: #374151;
    line-height: 1.75;
    text-align: justify;
  }
  .resp-clause strong { color: #022c22; }
  .resp-sign-row {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 40px;
    margin-top: 24px;
  }
  .resp-sign-field {
    display: flex; flex-direction: column; gap: 6px;
  }
  .resp-sign-line {
    border-bottom: 1px solid #022c22;
    height: 28px;
  }
  .resp-sign-caption {
    font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
    color: #6b7280; font-weight: 600;
  }
</style>
</head>
<body>

<!-- PRINT BAR -->
<div class="print-bar">
  <div class="print-bar-text">
    <span class="shield-icon">&#128737;</span>
    <span><strong>SpamShield AI</strong> — Informe Oficial de Denuncia</span>
    <span class="case-num">${d.caseNumber}</span>
  </div>
  <div>
    <button class="print-btn" onclick="window.print()">Imprimir / Guardar como PDF</button>
    <button class="print-btn print-btn-close" onclick="window.close()">Cerrar</button>
  </div>
</div>

<!-- ============ PAGE 1: COVER ============ -->
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
    <div class="cover-classification">Documento Oficial — Confidencial</div>
  </div>

  <div class="cover-body">
    <div class="cover-eyebrow">Informe Oficial de Denuncia</div>
    <h1 class="cover-h1">Denuncia Formal por<br>Correo Electrónico Malicioso</h1>
    <p class="cover-subtitle">
      Documento técnico-forense de respaldo para la presentación de denuncias
      por delitos informáticos ante las autoridades competentes de la
      República de Chile, conforme a la Ley 21.459 y normativa conexa.
    </p>

    <div class="cover-case-box">
      <div class="cover-case-label">Número de Caso Oficial</div>
      <div class="cover-case-number">${d.caseNumber}</div>
      <div class="cover-case-sub">Generado por SpamShield AI · Caso único e intransferible</div>
    </div>

    <div class="cover-authority-box">
      <div class="cover-authority-label">Autoridad Destinataria</div>
      <div class="cover-authority-name">${escapeHtml(d.authority.name)}</div>
    </div>

    <div class="cover-meta-grid">
      <div class="cover-meta-item">
        <div class="cover-meta-label">Fecha de Emisión</div>
        <div class="cover-meta-value">${d.declarationDate}</div>
      </div>
      <div class="cover-meta-item">
        <div class="cover-meta-label">Veredicto</div>
        <div class="cover-meta-value" style="color:${d.verdictColor};font-weight:700;">${d.verdict} · ${d.spamScore}/100</div>
      </div>
      <div class="cover-meta-item">
        <div class="cover-meta-label">Clasificación</div>
        <div class="cover-meta-value" style="color:#fca5a5;">CONFIDENCIAL</div>
      </div>
    </div>

    <div class="cover-hash-row">
      <div class="cover-hash-label">Hash de Integridad (SHA-256)</div>
      <div class="cover-hash-value">${d.integrityHash.substring(0, 48)}…</div>
    </div>
  </div>

  <div class="cover-footer">
    <span class="cover-footer-text">SpamShield AI © ${new Date().getFullYear()} — Documento Oficial de Denuncia</span>
    <span class="cover-footer-id">${d.caseNumber}</span>
  </div>
</div>

<!-- ============ PAGE 2: DATOS DEL DENUNCIANTE ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Identificación del Denunciante</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#10b98120;color:#10b981">D</div>
      <div class="section-title">Datos Personales del Denunciante</div>
    </div>
    <div class="section-divider"></div>

    <table class="info-table">
      <tr>
        <td class="info-label">Nombre Completo</td>
        <td class="info-value" style="font-weight:600;color:#022c22;">${escapeHtml(d.denunciante.nombre)}</td>
      </tr>
      <tr>
        <td class="info-label">RUT</td>
        <td class="info-value" style="font-family:'Courier New',monospace;">${escapeHtml(d.denunciante.rut)}</td>
      </tr>
      <tr>
        <td class="info-label">Nacionalidad</td>
        <td class="info-value">${escapeHtml(d.denunciante.nacionalidad)}</td>
      </tr>
      <tr>
        <td class="info-label">Domicilio</td>
        <td class="info-value">${escapeHtml(d.denunciante.domicilio)}</td>
      </tr>
      <tr>
        <td class="info-label">Teléfono de Contacto</td>
        <td class="info-value">${escapeHtml(d.denunciante.telefono)}</td>
      </tr>
      <tr>
        <td class="info-label">Correo Electrónico</td>
        <td class="info-value" style="font-family:'Courier New',monospace;">${escapeHtml(d.denunciante.email)}</td>
      </tr>
      <tr>
        <td class="info-label">Relación con el Incidente</td>
        <td class="info-value">
          <span class="badge badge-emerald">${escapeHtml(RELACION_LABELS[d.denunciante.relacion] || d.denunciante.relacion)}</span>
        </td>
      </tr>
    </table>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#064e3b20;color:#064e3b">A</div>
      <div class="section-title">Autoridad Destinataria</div>
    </div>
    <div class="section-divider"></div>
    <table class="info-table">
      <tr>
        <td class="info-label">Autoridad</td>
        <td class="info-value" style="font-weight:600;color:#022c22;">${escapeHtml(d.authority.name)}</td>
      </tr>
      <tr>
        <td class="info-label">Competencia</td>
        <td class="info-value">${escapeHtml(d.authority.desc)}</td>
      </tr>
      <tr>
        <td class="info-label">Sitio Web</td>
        <td class="info-value" style="font-family:'Courier New',monospace;color:#047857;">${escapeHtml(d.authority.url)}</td>
      </tr>
      <tr>
        <td class="info-label">Dirección / Lugar de Presentación</td>
        <td class="info-value">${escapeHtml(d.authority.address)}</td>
      </tr>
    </table>
  </div>

  <div class="page-footer">
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 2 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

<!-- ============ PAGE 3: DECLARACIÓN JURADA ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Declaración Jurada y Acuerdo de Responsabilidad</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#dc262620;color:#dc2626">&#9763;</div>
      <div class="section-title">Declaración Jurada de Responsabilidad</div>
    </div>
    <div class="section-divider"></div>

    <div class="decl-box">
      <div class="decl-title">Declaración Jurada de Responsabilidad</div>

      <p class="decl-preamble">
        Yo, <strong>${escapeHtml(d.denunciante.nombre)}</strong>,
        RUT <strong style="font-family:'Courier New',monospace;">${escapeHtml(d.denunciante.rut)}</strong>,
        bajo declaración solemne y con conocimiento de las penas establecidas en el
        Artículo 210 del Código Penal de Chile por falsas declaraciones ante autoridad,
        declaro que:
      </p>

      <ul class="decl-list">
        ${declarationPointsHtml}
      </ul>

      <div class="decl-base-legal">
        <strong>Base Legal:</strong> Ley 21.663 (Marco de Ciberseguridad),
        Ley 21.459 (Delitos Informáticos — Art. 211B phishing),
        Ley 21.719 (Protección de Datos Personales),
        Art. 210 Código Penal (falsa declaración).
      </div>

      <div class="signature-block">
        <div class="signature-rendered">${escapeHtml(d.firmaDigital)}</div>
        <div class="signature-caption">Firma Digital del Denunciante</div>
        <div class="signature-date">Fecha de la declaración: ${d.declarationDate}</div>
        <div class="signature-note">
          La firma digital equivale a firma manuscrita conforme a la
          <strong>Ley 19.799 sobre Documentos Electrónicos, Firma Electrónica y Servicios de Certificación</strong>
          de la República de Chile.
        </div>
      </div>
    </div>
  </div>

  <div class="page-footer">
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 3 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

<!-- ============ PAGE 4: EXECUTIVE SUMMARY + THREAT METRICS ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Resumen Ejecutivo y Métricas de Amenaza</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:${d.verdictColor}20;color:${d.verdictColor}">!</div>
      <div class="section-title">Veredicto Oficial del Análisis</div>
    </div>
    <div class="section-divider"></div>

    <div class="exec-box">
      <div class="exec-box-title">Veredicto: ${d.verdict} — Puntuación ${d.spamScore}/100</div>
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

  <div class="page-footer">
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 4 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

<!-- ============ PAGE 5: EMAIL METADATA + FORENSIC ANALYSIS ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Metadatos del Correo y Análisis Forense</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
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
        <td class="info-label">Fuente de Ingreso</td>
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
        <td class="info-label">Identificador Interno</td>
        <td class="info-value" style="font-family:'Courier New',monospace;font-size:11px;color:#6b7280;">${d.scanId}</td>
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
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 5 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

<!-- ============ PAGE 6: RECOMMENDATIONS + EMAIL PREVIEW ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Recomendaciones de Seguridad y Extracto del Correo</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#10b98120;color:#10b981">&#10003;</div>
      <div class="section-title">Recomendaciones de Seguridad</div>
    </div>
    <div class="section-divider"></div>
    <div class="md-content">
      ${renderMarkdown(d.recommendations)}
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#6b728020;color:#6b7280">E</div>
      <div class="section-title">Extracto del Correo Original</div>
    </div>
    <div class="section-divider"></div>
    <div class="email-preview">${emailPreviewText}</div>
  </div>

  <div class="page-footer">
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 6 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

<!-- ============ PAGE 7: LEGAL FRAMEWORK + CHAIN OF CUSTODY + HASH ============ -->
<div class="page">
  <div class="page-header">
    <div class="page-header-left">
      <div class="shield-dot"></div>
      <span>Marco Legal, Cadena de Custodia e Integridad</span>
    </div>
    <div class="page-header-right">${d.caseNumber}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#022c2220;color:#022c22">L</div>
      <div class="section-title">Marco Legal Aplicable</div>
    </div>
    <div class="section-divider"></div>
    ${lawsHtml}
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#3b82f620;color:#3b82f6">U</div>
      <div class="section-title">Autoridades Competentes</div>
    </div>
    <div class="section-divider"></div>
    <div class="auth-grid">
      <div class="auth-card ${d.autoridadKey === 'pdi' || d.autoridadKey === 'todas' ? 'active' : ''}">
        <div class="auth-card-name">PDI — BRICIB (Brigada de Delitos Cibernéticos)</div>
        <div class="auth-card-desc">Cibercrimen, phishing, fraude electrónico y suplantación de identidad digital.</div>
        <div class="auth-card-contact">https://www.pdi.cl</div>
        <div class="auth-card-address">Av. Pedro Montt 2354, Santiago</div>
      </div>
      <div class="auth-card ${d.autoridadKey === 'carabineros' || d.autoridadKey === 'todas' ? 'active' : ''}">
        <div class="auth-card-name">Carabineros de Chile</div>
        <div class="auth-card-desc">Delitos en general y situaciones de peligro inminente. Emergencias: 133.</div>
        <div class="auth-card-contact">https://www.carabineros.cl</div>
        <div class="auth-card-address">Unidad policial (comisaría) más cercana</div>
      </div>
      <div class="auth-card ${d.autoridadKey === 'anci' || d.autoridadKey === 'todas' ? 'active' : ''}">
        <div class="auth-card-name">ANCI — Agencia Nacional de Ciberseguridad</div>
        <div class="auth-card-desc">Reporte de incidentes de ciberseguridad y coordinación de respuesta nacional.</div>
        <div class="auth-card-contact">https://csirt.gob.cl (transitoriamente)</div>
        <div class="auth-card-address">CSIRT Nacional — Reporte de incidentes en línea</div>
      </div>
      <div class="auth-card ${d.autoridadKey === 'fiscalia' || d.autoridadKey === 'todas' ? 'active' : ''}">
        <div class="auth-card-name">Fiscalía — Ministerio Público</div>
        <div class="auth-card-desc">Investigación formal de delitos informáticos conforme a la Ley 21.459.</div>
        <div class="auth-card-contact">https://www.fiscaliedeley.cl</div>
        <div class="auth-card-address">Fiscalía Local con competencia territorial</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#f59e0b20;color:#f59e0b">C</div>
      <div class="section-title">Cadena de Custodia</div>
    </div>
    <div class="section-divider"></div>
    ${custodyHtml}
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#0ea5e920;color:#0ea5e9">#</div>
      <div class="section-title">Hash de Integridad SHA-256</div>
    </div>
    <div class="section-divider"></div>
    <div class="integrity-box">
      <span class="integrity-label">SHA-256 (scanId + denunciante + fecha + análisis)</span>
      <div class="integrity-hash">${d.integrityHash}</div>
      <span class="integrity-note">
        Hash criptográfico calculado sobre el identificador del análisis, los datos
        personales del denunciante, la fecha de emisión y el contenido analizado.
        Permite verificar criptográficamente que el informe no ha sido modificado
        con posterioridad a su emisión.
      </span>
    </div>
    <div class="verification-box">
      <div class="verification-title">Instrucciones de Verificación</div>
      <div class="verification-text">
        Para verificar la autenticidad de este informe, contacte a SpamShield AI
        mediante el número de caso <strong style="font-family:'Courier New',monospace;">${d.caseNumber}</strong>
        y proporcione el hash SHA-256 completo mostrado arriba. El sistema
        confirmará la coincidencia del registro original.
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon" style="background:#dc262620;color:#dc2626">R</div>
      <div class="section-title">Cláusula de Responsabilidad (Firma Manuscrita)</div>
    </div>
    <div class="section-divider"></div>
    <div class="resp-clause">
      ${escapeHtml(fullDeclarationText)}
      <div class="resp-sign-row">
        <div class="resp-sign-field">
          <div class="resp-sign-line"></div>
          <span class="resp-sign-caption">Firma Manuscrita del Denunciante</span>
        </div>
        <div class="resp-sign-field">
          <div class="resp-sign-line"></div>
          <span class="resp-sign-caption">Fecha (DD / MM / AAAA)</span>
        </div>
      </div>
    </div>
  </div>

  <div class="page-footer">
    <span class="pf-left">${d.caseNumber}</span>
    <span class="pf-center">Página 7 de 7</span>
    <span class="pf-right">SpamShield AI — Documento Oficial de Denuncia</span>
  </div>
</div>

</body>
</html>`
}
