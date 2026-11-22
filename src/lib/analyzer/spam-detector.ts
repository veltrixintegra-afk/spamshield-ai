import { Signal } from './types'

/* ============================================================
   DETECTOR DE SPAM
   Detecta patrones típicos de correo spam mediante:
   - Palabras clave de urgencia/pressure
   - Ofertas engañosas
   - Solicitudes de información personal
   - Patrones de lenguaje spam
   ============================================================ */

// Palabras/frases de urgencia y presión psicológica
const URGENCY_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /urgente|inmediat[ao]|ahora mismo|sin demora/i, weight: 8, desc: 'Lenguaje de urgencia' },
  { regex: /últim[aoa]\s+(oportunidad|día|hor[ao]| chance)/i, weight: 9, desc: 'Falsa escasez temporal' },
  { regex: /(?:expire|venc)\s+(?:en|dentro de|hoy)/i, weight: 8, desc: 'Amenaza de expiración' },
  { regex: /actúa ya|no esperes|responde ya/i, weight: 7, desc: 'Llamado a acción inmediata' },
  { regex: /(?:antes de que sea )?(?:demasiado )?tarde/i, weight: 7, desc: 'FOMO - miedo a perder' },
  { regex: /solo (?:hoy|ahora|por hoy)/i, weight: 6, desc: 'Oferta temporal restrictiva' },
  { regex: /lim(?:itado|itados?)\s+(?:plazas|cupos|lugares|stock)/i, weight: 7, desc: 'Falsa escasez de stock' },
]

// Ofertas engañosas / ganancias financieras
const SCAM_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /ganaste|has ganado|felicitaciones.*gan/i, weight: 12, desc: 'Falsa notificación de premio' },
  { regex: /loter[ií]a|sorteo|premio.*mill/i, weight: 10, desc: 'Referencia a lotería/premio' },
  { regex: /herencia|fondo en custodia|dinero bloqueado/i, weight: 12, desc: 'Estafa de herencia/fondo' },
  { regex: /\$\s*\d{3,}|\d{1,3}(?:,\d{3})+\s*(?:d[ió]lares|USD|pesos|euros)/i, weight: 7, desc: 'Monto de dinero específico atractivo' },
  { regex: /inversi[óo]n.*garantizada|sin riesgo|doble tu (?:dinero|inversi)/i, weight: 11, desc: 'Promesa de ganancia garantizada' },
  { regex: /trabajo desde casa|gana dinero f[aá]cil|ingresos pasivos/i, weight: 9, desc: 'Esquema de dinero fácil' },
  { regex: /cr[ií]dito.*aprueba|pr[eé]stamo.*sin (?:cheque|revisi)/i, weight: 10, desc: 'Oferta de crédito sin verificación' },
  { regex: /bitcoin|crypto(?:currency)?\s+(?:duplica|triplica)/i, weight: 9, desc: 'Esquema cripto' },
]

// Solicitudes de información personal/financiera
const INFO_HARVEST_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /verifica (?:tu )?(?:cuenta|datos|informaci)/i, weight: 9, desc: 'Solicitud de verificación de datos' },
  { regex: /confirma (?:tu )?(?:contraseña|password|clave|pin|c[oó]digo)/i, weight: 14, desc: 'Solicitud directa de credenciales' },
  { regex: /actualiza (?:tus )?(?:datos|informaci[óo]n personal)/i, weight: 8, desc: 'Solicitud de actualización de datos' },
  { regex: /(?:tarjeta|card)\s+(?:de cr[eé]dito|n[uú]mero)/i, weight: 12, desc: 'Solicitud de tarjeta de crédito' },
  { regex: /(?:n[uú]mero )?(?:seguro|seguridad) social|SSN|DNI|RFC|CURP/i, weight: 12, desc: 'Solicitud de documento de identidad' },
  { regex: /datos bancarios|cuenta bancaria|n[uú]mero de cuenta/i, weight: 11, desc: 'Solicitud de datos bancarios' },
]

// Patrones de lenguaje típicos de spam
const LANGUAGE_PATTERNS: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /\b(?:FWD|RV)\s*:/i, weight: 2, desc: 'Marcado como reenvío' },
  { regex: /\b[A-Z]{10,}\b/g, weight: 4, desc: 'Palabras en mayúsculas (gritando)' },
  { regex: /¡{2,}|!{3,}|\?{3,}/g, weight: 3, desc: 'Signos de exclamación excesivos' },
  { regex: /\*\*[^*]+\*\*/g, weight: 2, desc: 'Texto en negrita markdown' },
  { regex: /(?:gratis|free)\s*!/gi, weight: 5, desc: 'Énfasis en gratuidad' },
  { regex: /(?:clic|click|haz clic|pulsa)\s+(?:aqu[ií]|aqu[íi]|here)/i, weight: 6, desc: 'Llamado a clic' },
]

// Dominios de email sospechosos (disposables/fake)
const SUSPICIOUS_DOMAINS = [
  'mailinator.com', 'guerrillamail.com', 'tempmail', '10minutemail',
  'throwaway', 'yopmail.com', 'sharklasers.com', 'getnada.com',
  'dispostable.com', 'temp-mail.org', 'fakeinbox',
]

// TLDs de alto riesgo
const HIGH_RISK_TLDS = /\.(tk|ml|ga|cf|gq|top|click|country|stream|download|loan|work|men|date|party|review|trade|science|racing|accountant)$/i

export function detectSpam(text: string, senderEmail?: string | null): Signal[] {
  const signals: Signal[] = []

  // ── Urgencia y presión ──
  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'spam',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Ofertas engañosas ──
  for (const pattern of SCAM_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'spam',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Cosecha de información ──
  for (const pattern of INFO_HARVEST_PATTERNS) {
    if (pattern.regex.test(text)) {
      signals.push({
        type: 'spam',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  // ── Patrones de lenguaje ──
  for (const pattern of LANGUAGE_PATTERNS) {
    const matches = text.match(pattern.regex)
    if (matches && matches.length > 0) {
      signals.push({
        type: 'spam',
        weight: pattern.weight * Math.min(matches.length, 3),
        description: `${pattern.desc} (${matches.length} ocurrencias)`,
        evidence: matches.slice(0, 3).join(', ').substring(0, 80),
      })
    }
  }

  // ── Análisis del dominio del remitente ──
  if (senderEmail) {
    const domain = senderEmail.split('@')?.[1]?.toLowerCase()
    if (domain) {
      if (SUSPICIOUS_DOMAINS.some(d => domain.includes(d))) {
        signals.push({
          type: 'spoofing',
          weight: 15,
          description: 'Dominio del remitente es un proveedor de email temporal/desechable',
          evidence: domain,
        })
      }
      if (HIGH_RISK_TLDS.test(domain)) {
        signals.push({
          type: 'spam',
          weight: 10,
          description: 'Dominio usa TLD de alto riesgo frecuentemente usado en spam',
          evidence: domain,
        })
      }
    }
  }

  return signals
}
