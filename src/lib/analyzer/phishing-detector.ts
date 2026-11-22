import { Signal } from './types'

/* ============================================================
   DETECTOR DE PHISHING
   Detecta intentos de suplantación de identidad mediante:
   - Análisis de URLs (mismatch, IP-based, shortened)
   - Typosquatting de dominios conocidos
   - Formularios de login falsos
   - Brand spoofing
   ============================================================ */

// Marcas/empresas más suplantadas
const KNOWN_BRANDS = [
  { name: 'PayPal', domains: ['paypal.com', 'paypal.es', 'paypal.es.com'] },
  { name: 'Google', domains: ['google.com', 'gmail.com', 'googlemail.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office365.com'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.es', 'amazon.com.mx', 'amazonaws.com'] },
  { name: 'Facebook', domains: ['facebook.com', 'fb.com'] },
  { name: 'Instagram', domains: ['instagram.com'] },
  { name: 'BBVA', domains: ['bbva.com', 'bbva.es', 'bbvamovil.com'] },
  { name: 'Santander', domains: ['santander.com', 'santander.es', 'santandermovil.com'] },
  { name: 'BancoEstado', domains: ['bancoestado.cl', 'bancoestadomovil.cl'] },
  { name: 'Banco de Chile', domains: ['bancochile.cl', 'bcibancochile.cl'] },
  { name: 'Bci', domains: ['bci.cl', 'bancobci.cl'] },
  { name: 'Davivienda', domains: ['davivienda.com', 'davivienda.cl'] },
  { name: 'Netflix', domains: ['netflix.com'] },
  { name: 'Spotify', domains: ['spotify.com'] },
  { name: 'LinkedIn', domains: ['linkedin.com'] },
  { name: 'Twitter/X', domains: ['twitter.com', 'x.com'] },
  { name: 'Mercado Libre', domains: ['mercadolibre.com', 'mercadolibre.cl', 'mercadolivre.com'] },
  { name: ' Mercado Pago', domains: ['mercadopago.com', 'mercadopago.cl'] },
  { name: 'IRS/SII', domains: ['irs.gov', 'sii.cl'] },
  { name: 'DHL', domains: ['dhl.com'] },
  { name: 'FedEx', domains: ['fedex.com'] },
  { name: 'Correos', domains: ['correos.es', 'correos.cl', 'chilexpress.cl'] },
  { name: 'Zoom', domains: ['zoom.us', 'zoom.com'] },
  { name: 'Slack', domains: ['slack.com'] },
]

// Calcula distancia de Levenshtein (para typosquatting)
function levenshtein(a: string, b: string): number {
  const matrix: number[][] = []
  for (let i = 0; i <= b.length; i++) matrix[i] = [i]
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
      }
    }
  }
  return matrix[b.length][a.length]
}

// Extrae URLs del texto
function extractUrls(text: string): Array<{ url: string; displayText?: string }> {
  const urls: Array<{ url: string; displayText?: string }> = []

  // URLs en texto plano
  const plainUrlRegex = /(https?:\/\/[^\s<>"']+)/gi
  let match: RegExpExecArray | null
  while ((match = plainUrlRegex.exec(text)) !== null) {
    urls.push({ url: match[1] })
  }

  // URLs en href de HTML
  const hrefRegex = /href=["']([^"']+)["'][^>]*>(?:[^<]*\s*)?([^<]+)?/gi
  while ((match = hrefRegex.exec(text)) !== null) {
    urls.push({ url: match[1], displayText: match[2]?.trim() })
  }

  // Markdown links [text](url)
  const mdRegex = /\[([^\]]+)\]\(([^)]+)\)/gi
  while ((match = mdRegex.exec(text)) !== null) {
    urls.push({ url: match[2], displayText: match[1] })
  }

  return urls
}

// Obtiene el dominio de una URL
function getDomain(url: string): string | null {
  try {
    const match = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:/\n?]+)/i)
    return match ? match[1].toLowerCase() : null
  } catch {
    return null
  }
}

export function detectPhishing(text: string, senderEmail?: string | null): Signal[] {
  const signals: Signal[] = []
  const urls = extractUrls(text)

  // ── URL basada en IP ──
  for (const { url } of urls) {
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
      signals.push({
        type: 'phishing',
        weight: 15,
        description: 'URL usa dirección IP en lugar de dominio (alta sospecha)',
        evidence: url.substring(0, 80),
      })
    }
  }

  // ── URLs acortadas ──
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at']
  for (const { url } of urls) {
    const domain = getDomain(url)
    if (domain && SHORTENERS.includes(domain)) {
      signals.push({
        type: 'phishing',
        weight: 8,
        description: 'URL acortada oculta el destino real',
        evidence: domain,
      })
    }
  }

  // ── Mismatch entre texto mostrado y URL real ──
  for (const { url, displayText } of urls) {
    if (!displayText) continue
    const urlDomain = getDomain(url)
    // Si el texto mostrado parece un dominio pero no coincide con la URL real
    const displayUrlMatch = displayText.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+\.[a-z]{2,})/i)
    if (displayUrlMatch && urlDomain) {
      const displayDomain = displayUrlMatch[1].toLowerCase()
      if (displayDomain !== urlDomain && !urlDomain.includes(displayDomain) && !displayDomain.includes(urlDomain)) {
        signals.push({
          type: 'phishing',
          weight: 14,
          description: 'El texto del enlace oculta una URL diferente (mismatch)',
          evidence: `Muestra: ${displayDomain} → Real: ${urlDomain}`,
        })
      }
    }
  }

  // ── Typosquatting de marcas conocidas ──
  const senderDomain = senderEmail?.split('@')?.[1]?.toLowerCase() || ''
  const allDomainsInText = [
    senderDomain,
    ...urls.map(u => getDomain(u.url)).filter(Boolean) as string[],
  ].filter(Boolean)

  for (const domain of allDomainsInText) {
    const baseName = domain.split('.')[0]
    for (const brand of KNOWN_BRANDS) {
      for (const legitDomain of brand.domains) {
        const legitBase = legitDomain.split('.')[0]
        if (baseName === legitBase && domain !== legitDomain) {
          // Mismo nombre base pero dominio diferente (e.g., paypal-secure.com vs paypal.com)
          signals.push({
            type: 'phishing',
            weight: 16,
            description: `Dominio suplanta a ${brand.name} (parece legítimo pero no lo es)`,
            evidence: `${domain} ≠ ${legitDomain}`,
          })
        } else if (baseName !== legitBase) {
          const dist = levenshtein(baseName, legitBase)
          if (dist >= 1 && dist <= 2 && baseName.length >= 4) {
            signals.push({
              type: 'phishing',
              weight: 13,
              description: `Typosquatting de ${brand.name} (dominio muy similar)`,
              evidence: `${domain} ≈ ${legitDomain}`,
            })
          }
        }
      }
    }
  }

  // ── Brand spoofing en el contenido ──
  const textLower = text.toLowerCase()
  for (const brand of KNOWN_BRANDS) {
    if (textLower.includes(brand.name.toLowerCase())) {
      // La marca se menciona pero el remitente no es de su dominio legítimo
      const senderFromLegit = brand.domains.some(d => senderDomain === d || senderDomain.endsWith('.' + d))
      if (!senderFromLegit && senderDomain) {
        signals.push({
          type: 'phishing',
          weight: 11,
          description: `Menciona ${brand.name} pero el remitente no es del dominio oficial`,
          evidence: `Remitente: ${senderDomain}`,
        })
      }
    }
  }

  // ── Formularios de login en el email ──
  if (/<form/i.test(text) && /(password|contraseña|passwd|pin)/i.test(text)) {
    signals.push({
      type: 'phishing',
      weight: 15,
      description: 'Formulario con campo de contraseña embebido en el correo',
    })
  }

  // ── Subdominios excesivos ──
  for (const { url } of urls) {
    const domain = getDomain(url)
    if (domain) {
      const parts = domain.split('.')
      // e.g., paypal.login.secure-verify.tk
      if (parts.length > 4) {
        signals.push({
          type: 'phishing',
          weight: 9,
          description: 'URL con subdominios anidados excesivos (técnica de ofuscación)',
          evidence: domain,
        })
      }
    }
  }

  // ── HTTP (sin S) para captura de datos ──
  for (const { url } of urls) {
    if (/^http:\/\//i.test(url) && /(login|signin|account|cuenta|password|contraseña|verify|verifica)/i.test(url)) {
      signals.push({
        type: 'phishing',
        weight: 12,
        description: 'URL HTTP (sin cifrar) solicita datos sensibles',
        evidence: url.substring(0, 80),
      })
    }
  }

  return signals
}
