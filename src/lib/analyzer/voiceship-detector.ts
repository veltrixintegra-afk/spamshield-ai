import { Signal } from './types'

/* ============================================================
   DETECTOR DE VOICESHIP / CEO FRAUD
   Detecta estafas de suplantación de autoridad mediante:
   - Suplantación de directivos/CEO
   - Solicitudes urgentes de transferencia
   - Pedidos de confidencialidad
   - Instrucciones de saltar cadena de mando
   ============================================================ */

// Patrones de suplantación de autoridad
const AUTHORITY_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /(?:soy|habla|le escribe)\s+(?:el\s+)?(?:CEO|presidente|director|gerente|jefe)/i, weight: 15, desc: 'Autoidentificación como directivo' },
  { regex: /\b(?:CEO|CFO|CTO|presidente|director (?:general|financiero|ejecutivo))\b/i, weight: 10, desc: 'Mención de cargo directivo' },
  { regex: /(?:tu (?:jefe|supervisor|director)|el (?:jefe|director)) (?:me|te) (?:ha|había) (?:pedido|solicitado|encargado)/i, weight: 12, desc: 'Referencia a instrucción de superior' },
  { regex: /(?:necesito|requiero) (?:tu|su) (?:apoyo|ayuda|asistencia) (?:urgente|inmediata)/i, weight: 11, desc: 'Solicitud urgente de asistencia' },
]

// Patrones de transferencia financiera
const FINANCIAL_REQUEST_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /(?:transferencia|transferir)\s+(?:de\s+)?(?:dinero|fondos|pago)/i, weight: 15, desc: 'Solicitud de transferencia de fondos' },
  { regex: /(?:pago|transferencia)\s+(?:urgente|inmediato|hoy|ahora)/i, weight: 13, desc: 'Pago con urgencia temporal' },
  { regex: /(?:realiza|realizar|efectuar) (?:el\s+)?(?:pago|transferencia)\s+(?:a|para)/i, weight: 12, desc: 'Instrucción de pago a tercero' },
  { regex: /\b(?:wire|SWIFT|IBAN)\b/i, weight: 8, desc: 'Referencia a transferencia internacional' },
  { regex: /(?:cuenta|iban)\s+(?:n[uú]mero|n°)\s*[:.]?\s*[A-Z0-9]{8,}/i, weight: 12, desc: 'Número de cuenta bancaria embebido' },
  { regex: /(?:criptomoneda|bitcoin|BTC|USDT|wallet|billetera)/i, weight: 10, desc: 'Solicitud en criptomonedas (difícil de rastrear)' },
  { regex: /(?:tarjeta regalo|gift card|google play|itunes|amazon.*tarjeta)/i, weight: 12, desc: 'Solicitud de tarjetas regalo (típico CEO fraud)' },
]

// Patrones de secreto/confidencialidad
const SECRECY_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /(?:confidencial|privado|secreto)\s*[,-]?\s*(?:por favor|no)/i, weight: 12, desc: 'Solicitud de confidencialidad' },
  { regex: /(?:no|nunca) (?:lo )?(?:comentes|diga[s]?|menciones|informes|comunique)/i, weight: 11, desc: 'Instrucción de no informar a otros' },
  { regex: /(?:entre (?:tú|usted) y yo|solo (?:para ti|entre nosotros))/i, weight: 10, desc: 'Falsa intimidad/secreto compartido' },
  { regex: /(?:evita|no) (?:hablar|comentar) (?:con|del (?:tema|asunto) (?:con)) (?:nadie|compañeros|departamento)/i, weight: 12, desc: 'Aislamiento de la víctima' },
]

// Patrones de saltar cadena de mando
const BYPASS_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /(?:no|sin) (?:necesidad de|pasar por) (?:aprobaci|autorizaci|verificaci)/i, weight: 14, desc: 'Instrucción de saltar aprobaciones' },
  { regex: /(?:directo|directamente)\s+(?:a ti|contigo|conmigo)/i, weight: 9, desc: 'Comunicación directa evitando canales' },
  { regex: /(?:omite|ignora) (?:el )?(?:proceso|procedimiento|protocolo)/i, weight: 13, desc: 'Pedir omitir procedimientos' },
  { regex: /(?:solo yo|solo yo puedo) (?:autorizar|aprobar)/i, weight: 11, desc: 'Centralización de autoridad' },
]

// Patrones de ingeniería social emocional
const EMOTIONAL_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /(?:familia|hijo[s]?|esposa|cónyuge) (?:en (?:peligro|riesgo)|enferm)/i, weight: 14, desc: 'Manipulación emocional familiar' },
  { regex: /(?:perderás|puede[r]?\s+perder) (?:el\s+)?(?:trabajo|empleo|puesto)/i, weight: 12, desc: 'Amenaza de pérdida de empleo' },
  { regex: /(?:denuncia|investigaci[óo]n|legal) (?:contra ti|en tu contra)/i, weight: 11, desc: 'Amenaza legal' },
  { regex: /(?:he\s+estado|he estado) (?:pensando|considerando) (?:en ti|en tu (?:futuro|ascenso))/i, weight: 9, desc: 'Falsa promesa de beneficio' },
  { regex: /(?:conf[ií]o|dep[en]do|cuento) (?:plenamente|totalmente) (?:de|en) ti/i, weight: 10, desc: 'Falsa confianza/dependencia' },
]

export function detectVoiceship(text: string, senderEmail?: string | null): Signal[] {
  const signals: Signal[] = []

  // ── Autoridad ──
  for (const pattern of AUTHORITY_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'voiceship',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Solicitudes financieras ──
  for (const pattern of FINANCIAL_REQUEST_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'voiceship',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Confidencialidad ──
  for (const pattern of SECRECY_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'voiceship',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Saltar cadena de mando ──
  for (const pattern of BYPASS_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'voiceship',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Ingeniería social emocional ──
  for (const pattern of EMOTIONAL_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'social',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Sender domain mismatch (spoofing detection) ──
  if (senderEmail) {
    const domain = senderEmail.split('@')?.[1]?.toLowerCase()
    if (domain) {
      // Free email providers para un "CEO"
      const FREE_PROVIDERS = ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'live.com', 'protonmail.com', 'icloud.com']
      // Si el texto menciona ser directivo pero usa email gratuito
      if (FREE_PROVIDERS.includes(domain) && /(?:CEO|presidente|director|gerente|jefe)/i.test(text)) {
        signals.push({
          type: 'voiceship',
          weight: 14,
          description: 'Supuesta autoridad directiva usando email gratuito (no corporativo)',
          evidence: `${senderEmail}`,
        })
      }
    }
  }

  // ── Combinación: urgencia + transferencia + secreto = voiceship crítico ──
  const hasUrgency = /(?:urgente|inmediat|hoy|ahora)/i.test(text)
  const hasTransfer = /(?:transfer|pago|wire|bitcoin|gift card|tarjeta regalo)/i.test(text)
  const hasSecrecy = /(?:confidencial|no comentes|entre (?:tú|usted))/i.test(text)

  if (hasUrgency && hasTransfer && hasSecrecy) {
    signals.push({
      type: 'voiceship',
      weight: 20,
      description: 'TRÍADA DE VOICESHIP DETECTADA: urgencia + transferencia + confidencialidad',
    })
  }

  return signals
}
