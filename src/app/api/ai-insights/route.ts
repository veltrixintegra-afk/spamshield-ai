import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET() {
  try {
    const allScans = await db.emailScan.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50,
    })

    if (allScans.length < 2) {
      return NextResponse.json({ insights: 'Se necesitan al menos 2 análisis para generar insights inteligentes.' })
    }

    const totalScans = allScans.length
    const spamCount = allScans.filter((s) => s.isSpam === true).length
    const aiCount = allScans.filter((s) => s.isAiGenerated === true).length
    const safeCount = totalScans - spamCount
    const avgSpamScore = Math.round(allScans.reduce((a, s) => a + (s.spamScore ?? 0), 0) / totalScans)
    const spamRate = Math.round((spamCount / totalScans) * 100)
    const aiRate = Math.round((aiCount / totalScans) * 100)

    const threatDist: Record<string, number> = {}
    for (const s of allScans) {
      const t = s.threatType || 'none'
      threatDist[t] = (threatDist[t] || 0) + 1
    }

    // Top threat type
    const sortedThreats = Object.entries(threatDist).sort((a, b) => b[1] - a[1])
    const topThreat = sortedThreats.find(([t]) => t !== 'none')

    // Top spam senders
    const senderMap: Record<string, { count: number; avgScore: number; threats: string[] }> = {}
    for (const s of allScans.filter((s) => s.isSpam === true)) {
      const sender = s.senderEmail || s.senderName || 'Desconocido'
      if (!senderMap[sender]) senderMap[sender] = { count: 0, avgScore: 0, threats: [] }
      senderMap[sender].count++
      senderMap[sender].avgScore += s.spamScore ?? 0
      if (s.threatType && s.threatType !== 'none') senderMap[sender].threats.push(s.threatType)
    }
    const topSenders = Object.entries(senderMap)
      .map(([sender, data]) => ({
        sender,
        count: data.count,
        avgScore: Math.round(data.avgScore / data.count),
        threats: [...new Set(data.threats)],
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 3)

    // ── Generar insights automáticamente (motor propio) ──
    const insights = generateInsights({
      totalScans,
      spamCount,
      aiCount,
      safeCount,
      avgSpamScore,
      spamRate,
      aiRate,
      topThreat,
      topSenders,
    })

    return NextResponse.json({ insights })
  } catch (error) {
    console.error('Error generating insights:', error)
    return NextResponse.json({ insights: 'Error al generar insights. Intenta de nuevo.' }, { status: 500 })
  }
}

function generateInsights(data: {
  totalScans: number
  spamCount: number
  aiCount: number
  safeCount: number
  avgSpamScore: number
  spamRate: number
  aiRate: number
  topThreat: [string, number] | undefined
  topSenders: Array<{ sender: string; count: number; avgScore: number; threats: string[] }>
}): string {
  const lines: string[] = []

  // Insight 1: Threat level overall
  if (data.spamRate >= 60) {
    lines.push(`• Nivel de amenaza ALTO: ${data.spamRate}% de los correos analizados (${data.spamCount} de ${data.totalScans}) son spam. Se recomienda reforzar filtros de correo.`)
  } else if (data.spamRate >= 30) {
    lines.push(`• Nivel de amenaza MODERADO: ${data.spamRate}% de los correos (${data.spamCount} de ${data.totalScans}) son spam. Mantén vigilancia activa.`)
  } else {
    lines.push(`• Nivel de amenaza BAJO: Solo ${data.spamRate}% de los correos (${data.spamCount} de ${data.totalScans}) son spam. Tu bandeja está relativamente segura.`)
  }

  // Insight 2: Top threat type
  if (data.topThreat) {
    const [threatType, count] = data.topThreat
    const labels: Record<string, string> = {
      phishing: 'Phishing (suplantación de identidad)',
      voiceship: 'Voiceship / CEO Fraud',
      spoofing: 'Spoofing',
      social_engineering: 'Ingeniería social',
      malware: 'Malware',
    }
    const label = labels[threatType] || threatType
    const pct = Math.round((count / data.totalScans) * 100)
    lines.push(`• Amenaza predominante: ${label} detectada en ${count} correos (${pct}% del total).`)
  }

  // Insight 3: AI-generated content
  if (data.aiRate >= 40) {
    lines.push(`• ${data.aiRate}% de los correos muestran señales de ser generados por IA (${data.aiCount} correos). Los atacantes podrían estar automatizando campañas con modelos de lenguaje.`)
  } else if (data.aiRate > 0) {
    lines.push(`• ${data.aiRate}% de los correos (${data.aiCount}) presentan indicadores de contenido generado por IA.`)
  }

  // Insight 4: Top spam sender
  if (data.topSenders.length > 0) {
    const top = data.topSenders[0]
    const senderShort = top.sender.length > 30 ? top.sender.substring(0, 30) + '...' : top.sender
    lines.push(`• Remitente más frecuente en spam: ${senderShort} (${top.count} correos, score promedio ${top.avgScore}%).`)
  }

  // Insight 5: Score trend
  if (data.avgSpamScore >= 50) {
    lines.push(`• Score promedio de amenaza: ${data.avgSpamScore}/100. Los correos analizados presentan un nivel de peligrosidad elevado en promedio.`)
  } else {
    lines.push(`• Score promedio de amenaza: ${data.avgSpamScore}/100. La mayoría de correos analizados son de riesgo bajo.`)
  }

  return lines.join('\n')
}
