import { Signal } from './types'

/* ============================================================
   DETECTOR DE CONTENIDO GENERADO POR IA
   Detecta si un texto fue generado por IA mediante:
   - Análisis de burstiness (variación en longitud de oraciones)
   - Análisis de perplexity aproximado
   - Patrones de estructura demasiado uniforme
   - Fórmulas de cortesía estereotipadas
   - Frases genéricas de IA
   ============================================================ */

// Frases estereotipadas que modelos de IA usan frecuentemente
const AI_STEREOTYPED_PHRASES: Array<{ regex: RegExp; weight: number; desc: string }> = [
  { regex: /en (?:este|el) (?:mundo digital|entorno digital|paisaje digital) de hoy/i, weight: 8, desc: 'Frase introductoria típica de IA' },
  { regex: /en conclusi[óo]n|en resumen|para concluir/i, weight: 6, desc: 'Cierre formal genérico' },
  { regex: /es (?:importante|crucial|esencial|vital) (?:que|notar)/i, weight: 7, desc: 'Énfasis formulaico de IA' },
  { regex: /(?:como )?(?:siempre|en general|por lo general)/i, weight: 4, desc: 'Generalización vaga' },
  { regex: /(?:además|por otra parte|por otro lado|asimismo)\s*,/i, weight: 4, desc: 'Conectores formulaicos' },
  { regex: /(?:cabe (?:mencionar|destacar|señalar)|vale la pena (?:mencionar|notar))/i, weight: 7, desc: 'Fórmula de énfasis de IA' },
  { regex: /(?:espero|conf[ií]o) que este (?:mensaje|correo|email) (?:le|te) (?:encuentre|haya encontrado) (?:bien|sano y salvo)/i, weight: 10, desc: 'Saludo formulaico clásico de IA' },
  { regex: /(?:no dude|no dudes) (?:en|de) (?:contactarme|comunicarse|escribir)/i, weight: 7, desc: 'Cierre de cortesía genérico' },
  { regex: /(?:comprender|entender) (?:la )?(?:importancia|necesidad) de/i, weight: 7, desc: 'Frase de comprensión formulaica' },
  { regex: /(?:garantizar|asegurar) (?:la )?(?:m[aá]xima|la mejor) (?:calidad|seguridad|eficiencia)/i, weight: 7, desc: 'Promesa formulaica de calidad' },
  { regex: /(?:enfoque|enfoques) (?:hol[ií]stico|integral)/i, weight: 6, desc: 'Jerga corporativa de IA' },
  { regex: /(?:navegar|recorrer) (?:este|el) (?:proceso|camino|viaje)/i, weight: 6, desc: 'Metáfora formulaica' },
  { regex: /(?:al final del d[íi]a|en [úu]ltima instancia)/i, weight: 5, desc: 'Cliché de IA' },
  { regex: /(?:profundamente|profundamente) (?:comprometido|dedicado|agradecido)/i, weight: 6, desc: 'Adverbio intenso formulaico' },
  { regex: /(?:una (?:variedad|gama) de|una amplia (?:variedad|gama) de)/i, weight: 6, desc: 'Frase de enumeración vaga' },
  { regex: /jugar (?:un )?papel (?:crucial|vital|importante|clave)/i, weight: 6, desc: 'Metáfora formulaica de IA' },
]

// Dividir texto en oraciones
function splitSentences(text: string): string[] {
  return text
    .replace(/([.!?]+)\s+/g, '$1\n')
    .split(/\n+/)
    .map(s => s.trim())
    .filter(s => s.length > 10)
}

// Calcula burstiness (variación en longitud de oraciones)
// Los humanos tienen alta burstiness (oraciones de longitud muy variable)
// La IA tiende a producir oraciones de longitud más uniforme
function calculateBurstiness(sentences: string[]): number {
  if (sentences.length < 3) return 50 // neutral

  const lengths = sentences.map(s => s.split(/\s+/).length)
  const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length
  const variance = lengths.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / lengths.length
  const stdDev = Math.sqrt(variance)
  // Coeficiente de variación
  const cv = mean > 0 ? stdDev / mean : 0

  // CV humano: ~0.4-0.8, IA: ~0.15-0.3
  // Convertimos a score 0-100 donde 100 = claramente IA
  const aiScore = Math.max(0, Math.min(100, (0.5 - cv) / 0.5 * 100))
  return aiScore
}

// Calcula repetición de estructura de oraciones
function calculateRepetition(sentences: string[]): number {
  if (sentences.length < 4) return 0

  // Detecta si las oraciones empiezan con las mismas palabras
  const starters = sentences.map(s => {
    const words = s.toLowerCase().split(/\s+/).slice(0, 2).join(' ')
    return words
  })
  const starterCounts: Record<string, number> = {}
  starters.forEach(s => { starterCounts[s] = (starterCounts[s] || 0) + 1 })

  const repetitiveStarts = Object.values(starterCounts).filter(c => c > 1).length
  const repetitionScore = Math.min(100, repetitiveStarts * 20)
  return repetitionScore
}

// Detecta puntuación perfecta (IA raramente comete errores)
function checkPunctuationPerfection(text: string): number {
  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0)
  if (sentences.length < 3) return 0

  let perfectCount = 0
  let totalChecked = 0

  for (const sentence of sentences) {
    const trimmed = sentence.trim()
    if (trimmed.length < 15) continue
    totalChecked++
    // Verifica mayúscula inicial y punto final
    if (/^[A-ZÁÉÍÓÚÑ]/.test(trimmed)) {
      perfectCount++
    }
  }

  if (totalChecked === 0) return 0
  // 100% perfectas = alta probabilidad de IA
  return totalChecked > 5 ? Math.round((perfectCount / totalChecked) * 50) : 0
}

// Detecta genéricos/sin personalización
function checkGenericContent(text: string): number {
  let score = 0
  // Sin nombre específico del destinatario
  if (!/\b(?:estimado|estimada|hola|querido)\s+(?!usuario|cliente|amigo|colega)\w+/i.test(text)) {
    score += 15
  }
  // Sin referencia a detalles específicos (fechas, números de cuenta, etc.)
  if (!/\b(?:n[uú]mero|referencia|caso|ticket|cuenta)\s*[:#]\s*\w+/i.test(text)) {
    score += 10
  }
  // Contenido que podría aplicarse a cualquier destinatario
  if (/estimado (?:cliente|usuario|amigo|colega)/i.test(text)) {
    score += 15
  }
  return score
}

export function detectAiContent(text: string): Signal[] {
  const signals: Signal[] = []

  // ── Frases estereotipadas de IA ──
  let phraseCount = 0
  for (const pattern of AI_STEREOTYPED_PHRASES) {
    if (pattern.regex.test(text)) {
      phraseCount++
      signals.push({
        type: 'ai',
        weight: pattern.weight,
        description: pattern.desc,
        evidence: text.match(pattern.regex)?.[0]?.substring(0, 80),
      })
    }
  }

  if (phraseCount >= 3) {
    signals.push({
      type: 'ai',
      weight: 15,
      description: 'Múltiples frases estereotipadas de IA detectadas (patrón de lenguaje modelo)',
    })
  }

  // ── Burstiness ──
  const sentences = splitSentences(text)
  const burstinessScore = calculateBurstiness(sentences)
  if (burstinessScore > 65 && sentences.length >= 4) {
    signals.push({
      type: 'ai',
      weight: Math.round(burstinessScore * 0.3),
      description: `Estructura de oraciones demasiado uniforme (burstiness bajo: ${burstinessScore.toFixed(0)}/100)`,
    })
  }

  // ── Repetición de estructura ──
  const repetitionScore = calculateRepetition(sentences)
  if (repetitionScore > 30) {
    signals.push({
      type: 'ai',
      weight: Math.round(repetitionScore * 0.2),
      description: 'Patrón repetitivo en el inicio de oraciones (típico de IA)',
    })
  }

  // ── Perfección de puntuación ──
  const punctScore = checkPunctuationPerfection(text)
  if (punctScore > 35) {
    signals.push({
      type: 'ai',
      weight: punctScore,
      description: 'Puntuación y mayúsculas excesivamente perfectas (sin errores humanos)',
    })
  }

  // ── Contenido genérico ──
  const genericScore = checkGenericContent(text)
  if (genericScore > 20) {
    signals.push({
      type: 'ai',
      weight: genericScore,
      description: 'Contenido sin personalización específica (aplicable a cualquier destinatario)',
    })
  }

  // ── Longitud promedio de palabras (IA usa palabras más largas) ──
  const words = text.split(/\s+/).filter(w => w.length > 0)
  if (words.length > 30) {
    const avgWordLen = words.reduce((a, w) => a + w.length, 0) / words.length
    if (avgWordLen > 6.5) {
      signals.push({
        type: 'ai',
        weight: 12,
        description: `Longitud promedio de palabras elevada (${avgWordLen.toFixed(1)} caracteres)`,
      })
    }
  }

  return signals
}
