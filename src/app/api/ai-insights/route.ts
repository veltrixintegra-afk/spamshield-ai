import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import ZAI from 'z-ai-web-dev-sdk'

export async function GET() {
  try {
    const allScans = await db.emailScan.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50,
    })

    if (allScans.length < 2) {
      return NextResponse.json({ insights: 'Se necesitan al menos 2 analisis para generar insights inteligentes.' })
    }

    const totalScans = allScans.length
    const spamCount = allScans.filter((s) => s.isSpam === true).length
    const aiCount = allScans.filter((s) => s.isAiGenerated === true).length
    const avgSpamScore = Math.round(allScans.reduce((a, s) => a + (s.spamScore ?? 0), 0) / totalScans)

    const threatDist: Record<string, number> = {}
    for (const s of allScans) {
      const t = s.threatType || 'none'
      threatDist[t] = (threatDist[t] || 0) + 1
    }

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

    const zai = await ZAI.create()
    const summaryData = { totalScans, spamCount, aiCount, avgSpamScore, threatDist, topSenders }

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'assistant',
          content:
            'Eres un analista de ciberseguridad senior que genera insights ejecutivos para un dashboard. Analiza las estadisticas y genera 3-4 observaciones clave en espanol, cada una de 1-2 oraciones. Se conciso pero informativo. Usa numeros especificos. Si hay patrones preocupantes, mencionalos. Formato: lista con vinetas usando "\u2022". NO uses markdown, solo texto plano.',
        },
        {
          role: 'user',
          content: `Datos de SpamShield AI:\n${JSON.stringify(summaryData, null, 2)}`,
        },
      ],
      thinking: { type: 'disabled' },
    })

    const insights = completion.choices?.[0]?.message?.content || 'No se pudieron generar insights en este momento.'
    return NextResponse.json({ insights })
  } catch (error) {
    console.error('Error generating AI insights:', error)
    return NextResponse.json({ insights: 'Error al generar insights. Intenta de nuevo.' }, { status: 500 })
  }
}
