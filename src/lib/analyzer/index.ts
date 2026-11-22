import { AnalysisResult, EmailInput, Signal } from './types'
import { detectSpam } from './spam-detector'
import { detectPhishing } from './phishing-detector'
import { detectAiContent } from './ai-detector'
import { detectVoiceship } from './voiceship-detector'

/* ============================================================
   ANALYZER - ORQUESTADOR PRINCIPAL
   Combina todos los detectores, calcula scores, y genera
   el informe completo en español.
   ============================================================ */

export function analyzeEmail(input: EmailInput): AnalysisResult {
  const text = input.content

  // Extraer remitente del contenido si no se proporcionó
  let senderEmail = input.sender || null
  if (!senderEmail) {
    const fromMatch = text.match(/From:\s*[^<]*<([^>]+)>/i) || text.match(/From:\s*(\S+@\S+)/i)
    if (fromMatch) senderEmail = fromMatch[1].trim()
  }

  // Extraer asunto
  let subject = input.subject || null
  if (!subject) {
    const subjectMatch = text.match(/Subject:\s*(.+)/i)
    if (subjectMatch) subject = subjectMatch[1].trim()
  }

  // ── Recopilar todas las señales ──
  const allSignals: Signal[] = [
    ...detectSpam(text, senderEmail),
    ...detectPhishing(text, senderEmail),
    ...detectAiContent(text),
    ...detectVoiceship(text, senderEmail),
  ]

  // ── Calcular score por tipo de amenaza ──
  const threatScores: Record<string, number> = {
    spam: 0,
    phishing: 0,
    voiceship: 0,
    ai: 0,
    spoofing: 0,
    social: 0,
  }

  for (const signal of allSignals) {
    threatScores[signal.type] = (threatScores[signal.type] || 0) + signal.weight
  }

  // ── Score de spam (0-100) ──
  // Combinación ponderada de todas las amenazas
  const rawScore =
    threatScores.spam * 1.0 +
    threatScores.phishing * 1.3 +
    threatScores.voiceship * 1.2 +
    threatScores.spoofing * 0.8 +
    threatScores.social * 0.7

  const spamScore = Math.min(100, Math.round(rawScore))

  // ── Score de IA (0-100) ──
  const aiConfidence = Math.min(100, Math.round(threatScores.ai))

  // ── Determinar tipo de amenaza principal ──
  let threatType: AnalysisResult['threatType'] = 'none'
  let maxThreatScore = 0

  const threatMap: Array<{ key: string; type: AnalysisResult['threatType'] }> = [
    { key: 'phishing', type: 'phishing' },
    { key: 'voiceship', type: 'voiceship' },
    { key: 'spoofing', type: 'spoofing' },
    { key: 'spam', type: 'social_engineering' },
    { key: 'social', type: 'social_engineering' },
  ]

  for (const { key, type } of threatMap) {
    if (threatScores[key] > maxThreatScore) {
      maxThreatScore = threatScores[key]
      threatType = type
    }
  }

  // Si no hay amenaza significante
  if (maxThreatScore < 15) {
    threatType = 'none'
  }

  const isSpam = spamScore >= 40
  const isAiGenerated = aiConfidence >= 45

  // ── Generar informe ──
  const senderAnalysis = generateSenderAnalysis(senderEmail, input.senderName, threatScores)
  const summary = generateSummary(spamScore, threatType, isAiGenerated, aiConfidence, allSignals)
  const detailedAnalysis = generateDetailedAnalysis(
    spamScore, threatType, isAiGenerated, aiConfidence, allSignals, threatScores, senderEmail, subject
  )
  const recommendations = generateRecommendations(threatType, isSpam, isAiGenerated, spamScore)

  return {
    isSpam,
    spamScore,
    isAiGenerated,
    aiConfidence,
    threatType,
    senderAnalysis,
    summary,
    detailedAnalysis,
    recommendations,
  }
}

/* ============================================================
   GENERADORES DE INFORME
   ============================================================ */

function generateSenderAnalysis(
  senderEmail: string | null,
  senderName: string | null,
  threatScores: Record<string, number>
): string {
  if (!senderEmail) {
    return 'No se pudo identificar la dirección del remitente desde el contenido proporcionado. Esto puede indicar que el correo no incluye encabezados estándar (From:), lo cual es inusual en correos legítimos. Se recomienda verificar el origen del mensaje antes de confiar en su contenido.'
  }

  const parts: string[] = []
  const domain = senderEmail.split('@')?.[1]?.toLowerCase()

  if (senderName) {
    parts.push(`El remitente se identifica como "${senderName}" (${senderEmail}).`)
  } else {
    parts.push(`Dirección del remitente: ${senderEmail}.`)
  }

  if (domain) {
    const FREE_PROVIDERS = ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'live.com', 'icloud.com', 'protonmail.com']
    const isFreeProvider = FREE_PROVIDERS.includes(domain)

    if (isFreeProvider) {
      if (threatScores.voiceship > 0) {
        parts.push(`⚠️ ALERTA: El correo menciona autoridad corporativa o solicitudes financieras, pero utiliza un proveedor de email gratuito (${domain}). Las empresas legítimas raramente usan cuentas gratuitas para comunicaciones oficiales o transacciones financieras. Esto es un indicador crítico de suplantación.`)
      } else {
        parts.push(`El dominio del remitente (${domain}) es un proveedor de email gratuito. Si bien esto no es necesariamente malicioso, debe verificarse si el remitente afirma representar a una organización que debería usar un dominio corporativo.`)
      }
    }

    const HIGH_RISK_TLDS = /\.(tk|ml|ga|cf|gq|top|click|country|stream|download|loan)$/i
    if (HIGH_RISK_TLDS.test(domain)) {
      parts.push(`⚠️ El dominio del remitente (${domain}) utiliza un TLD frecuentemente asociado con actividad maliciosa. Estos dominios son económicos o gratuitos y muy usados en campañas de spam y phishing.`)
    }

    const DISPOSABLE = ['mailinator', 'guerrillamail', 'tempmail', '10minutemail', 'throwaway', 'yopmail']
    if (DISPOSABLE.some(d => domain.includes(d))) {
      parts.push(`🚨 CRÍTICO: El dominio (${domain}) corresponde a un servicio de email temporal o desechable. Estos servicios permiten crear direcciones anónimas que se autodestruyen, siendo una herramienta común en ataques de phishing y fraudes.`)
    }
  }

  // Verificar si hay mismatch entre el nombre mostrado y el email
  if (senderName && senderEmail) {
    const nameLower = senderName.toLowerCase()
    const emailUser = senderEmail.split('@')[0]?.toLowerCase()
    if (emailUser && !nameLower.includes(emailUser.split('.')[0]) && !emailUser.includes(nameLower.split(' ')[0])) {
      parts.push(`⚠️ El nombre mostrado ("${senderName}") no coincide con la dirección de email. Esta discrepancia es una técnica común de spoofing donde el atacante muestra un nombre confiable pero usa una dirección diferente.`)
    }
  }

  if (threatScores.spoofing > 0) {
    parts.push('Se detectaron indicadores de spoofing en el dominio del remitente. La dirección puede estar suplantando a una organización legítima mediante variaciones sutiles en el dominio.')
  }

  if (parts.length === 1) {
    parts.push('No se detectaron anomalías obvias en el dominio del remitente, pero esto no garantiza legitimidad. Siempre verifique el contexto y contenido del mensaje.')
  }

  return parts.join(' ')
}

function generateSummary(
  spamScore: number,
  threatType: string,
  isAiGenerated: boolean,
  aiConfidence: number,
  signals: Signal[]
): string {
  const verdict = spamScore < 30 ? 'seguro' : spamScore < 60 ? 'sospechoso' : spamScore < 80 ? 'peligroso' : 'crítico'
  const threatLabel = getThreatLabel(threatType)

  let summary = `El análisis forense del correo electrónico arroja un score de amenaza de ${spamScore}/100, clasificándolo como ${verdict}.`

  if (threatType !== 'none') {
    summary += ` La amenaza principal detectada corresponde a: ${threatLabel}.`
  } else {
    summary += ` No se detectó una amenaza específica significativa.`
  }

  const criticalSignals = signals.filter(s => s.weight >= 12).slice(0, 3)
  if (criticalSignals.length > 0) {
    summary += ` Indicadores clave: ${criticalSignals.map(s => s.description.toLowerCase()).join(', ')}.`
  }

  if (isAiGenerated) {
    summary += ` Adicionalmente, el análisis de lenguaje detectó un ${aiConfidence}% de probabilidad de que el contenido haya sido generado por inteligencia artificial.`
  }

  return summary
}

function generateDetailedAnalysis(
  spamScore: number,
  threatType: string,
  isAiGenerated: boolean,
  aiConfidence: number,
  signals: Signal[],
  threatScores: Record<string, number>,
  senderEmail: string | null,
  subject: string | null
): string {
  const sections: string[] = []

  // ── Encabezado ──
  sections.push(`## Análisis Forense Detallado\n`)
  sections.push(`**Score de Amenaza:** ${spamScore}/100  \n**Tipo de Amenaza:** ${getThreatLabel(threatType)}  \n**Probabilidad IA:** ${aiConfidence}%\n`)

  // ── Metadatos del correo ──
  if (senderEmail || subject) {
    sections.push(`### Metadatos del Correo\n`)
    if (senderEmail) sections.push(`- **Remitente:** \`${senderEmail}\``)
    if (subject) sections.push(`- **Asunto:** "${subject}"`)
    sections.push('')
  }

  // ── Señales detectadas por categoría ──
  const categories: Array<{ key: string; title: string }> = [
    { key: 'spam', title: 'Indicadores de Spam' },
    { key: 'phishing', title: 'Análisis de Phishing' },
    { key: 'voiceship', title: 'Detección de Voiceship/CEO Fraud' },
    { key: 'spoofing', title: 'Indicadores de Spoofing' },
    { key: 'social', title: 'Ingeniería Social' },
    { key: 'ai', title: 'Análisis de Contenido IA' },
  ]

  for (const { key, title } of categories) {
    const catSignals = signals.filter(s => s.type === key)
    if (catSignals.length > 0) {
      sections.push(`### ${title}\n`)
      sections.push(`**Puntuación acumulada:** ${threatScores[key] || 0} puntos\n`)
      for (const signal of catSignals) {
        const bullet = `- ⚠️ ${signal.description}`
        sections.push(signal.evidence ? `${bullet} \n  - *Evidencia:* \`${signal.evidence}\`` : bullet)
      }
      sections.push('')
    }
  }

  // ── Evaluación técnica ──
  if (signals.length === 0) {
    sections.push(`### Evaluación Técnica\n`)
    sections.push(`No se detectaron indicadores de amenaza significativos en este correo. El contenido no presenta patrones típicos de spam, phishing, voiceship, ni señales de haber sido generado por IA. Sin embargo, la ausencia de indicadores no garantiza absoluta seguridad. Se recomienda mantener las buenas prácticas de seguridad habituales.`)
  } else {
    sections.push(`### Evaluación Técnica\n`)
    sections.push(`Se detectaron **${signals.length} indicadores** de amenaza con una puntuación total de **${signals.reduce((a, s) => a + s.weight, 0)} puntos**. `)

    if (spamScore >= 70) {
      sections.push(`El score elevado indica una alta probabilidad de que este correo sea malicioso. Se recomienda **no interactuar** con el contenido, no hacer clic en enlaces, y eliminar el correo inmediatamente.`)
    } else if (spamScore >= 40) {
      sections.push(`El score indica sospecha moderada. Si bien no todos los indicadores son concluyentes, la combinación de varios debería tratarse con precaución. Verifique el remitente por canales alternativos antes de tomar cualquier acción.`)
    } else {
      sections.push(`El score es bajo, indicando que el correo probablemente sea legítimo. Los pocos indicadores detectados pueden ser falsos positivos o características menores. Mantenga vigilancia estándar.`)
    }
    sections.push('')
  }

  // ── Análisis de IA ──
  if (isAiGenerated) {
    sections.push(`### Análisis de Generación por IA\n`)
    sections.push(`El sistema detectó un **${aiConfidence}% de probabilidad** de que este contenido haya sido generado por un modelo de inteligencia artificial. `)
    sections.push(`Indicadores observados incluyen: ${signals.filter(s => s.type === 'ai').map(s => s.description.toLowerCase()).join('; ')}.\n`)
    sections.push(`La generación de correo por IA no es necesariamente maliciosa, pero combinada con otros indicadores de amenaza, sugiere que un atacante podría estar usando IA para escalar campañas de phishing o crear mensajes más persuasivos a escala.`)
  }

  return sections.join('\n')
}

function generateRecommendations(
  threatType: string,
  isSpam: boolean,
  isAiGenerated: boolean,
  spamScore: number
): string {
  const recs: string[] = []

  recs.push(`## Recomendaciones de Seguridad\n`)

  if (spamScore >= 70) {
    recs.push(`### ⚠️ Acciones Inmediatas (CRÍTICO)\n`)
    recs.push(`- **NO** hagas clic en ningún enlace del correo`)
    recs.push(`- **NO** descargues ni abras adjuntos`)
    recs.push(`- **NO** respondas al remitente ni proporciones información`)
    recs.push(`- **Elimina** el correo permanentemente (no solo enviar a papelera)`)
    recs.push(`- Si ya interactuaste: **cambia contraseñas** y contacta a tu equipo de seguridad\n`)
  } else if (spamScore >= 40) {
    recs.push(`### ⚠️ Acciones Recomendadas (SOSPECHOSO)\n`)
    recs.push(`- Verifica la legitimidad del remitente por un **canal alternativo** (teléfono, otro email)`)
    recs.push(`- **No** hagas clic en enlaces hasta confirmar autenticidad`)
    recs.push(`- Si tienes dudas, reenvía el correo a tu equipo de seguridad para análisis`)
    recs.push(`- Marca el correo como spam en tu cliente de correo\n`)
  } else {
    recs.push(`### ✅ Buenas Prácticas (SEGURO)\n`)
    recs.push(`- El correo parece legítimo, pero mantén vigilancia estándar`)
    recs.push(`- Verifica el remitente antes de interactuar con enlaces o adjuntos`)
    recs.push(`- No compartas información sensible por correo sin cifrado\n`)
  }

  // Recomendaciones específicas por tipo de amenaza
  if (threatType === 'phishing') {
    recs.push(`### 🎣 Específicas para Phishing\n`)
    recs.push(`- Si introdujiste credenciales: **cambia tu contraseña inmediatamente**`)
    recs.push(`- Activa **autenticación de dos factores (2FA)** en todas tus cuentas`)
    recs.push(`- Reporta el phishing a la organización suplantada`)
    recs.push(`- Monitorea tus cuentas financieras por actividad sospechosa\n`)
  }

  if (threatType === 'voiceship') {
    recs.push(`### 🎙️ Específicas para Voiceship/CEO Fraud\n`)
    recs.push(`- **Verifica la solicitud** llamando directamente al directivo (usa un número conocido, no del correo)`)
    recs.push(`- **No realices transferencias** basadas únicamente en un correo`)
    recs.push(`- Reporta el intento a tu departamento de seguridad/TI`)
    recs.push(`- Sigue el protocolo de verificación dual para transferencias`)
    recs.push(`- Educa al equipo sobre este tipo de estafa\n`)
  }

  if (isAiGenerated) {
    recs.push(`### 🤖 Sobre Contenido Generado por IA\n`)
    recs.push(`- Ten en cuenta que los atacantes usan IA para crear mensajes más persuasivos`)
    recs.push(`- La perfección gramatical NO es garantía de legitimidad`)
    recs.push(`- Verifica siempre el contexto y el remitente, no solo el estilo del mensaje`)
    recs.push(`- Desconfía de correos con estructura excesivamente uniforme o fórmulas repetitivas\n`)
  }

  if (threatType === 'spoofing') {
    recs.push(`### 🎭 Específicas para Spoofing\n`)
    recs.push(`- Examina los encabezados completos del correo para verificar la ruta`)
    recs.push(`- Compara el dominio del remitente letra por letra con el legítimo`)
    recs.push(`- Reporta el intento de suplantación al proveedor del email`)
    recs.push(`- Configura SPF, DKIM y DMARC en tu propio dominio si lo administras\n`)
  }

  // Recomendaciones generales
  recs.push(`### 📋 Recomendaciones Generales\n`)
  recs.push(`- Mantén tu software y antivirus actualizados`)
  recs.push(`- Usa un gestor de contraseñas con contraseñas únicas por servicio`)
  recs.push(`- Educa continuamente a tu equipo sobre amenazas de correo`)
  recs.push(`- Reporta correos sospechosos a las autoridades correspondientes (ej. SII, banco)`)

  return recs.join('\n')
}

function getThreatLabel(type: string): string {
  const map: Record<string, string> = {
    phishing: 'Phishing (Suplantación de Identidad)',
    voiceship: 'Voiceship / CEO Fraud (Estafa de Autoridad)',
    spoofing: 'Spoofing (Falsificación de Remitente)',
    malware: 'Malware (Software Malicioso)',
    social_engineering: 'Ingeniería Social',
    none: 'Sin Amenaza Detectada',
  }
  return map[type] || type
}
