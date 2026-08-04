import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET() {
  try {
    const allScans = await db.emailScan.findMany({
      orderBy: { createdAt: 'desc' },
    })

    const totalScans = allScans.length
    const spamCount = allScans.filter((s) => s.isSpam === true).length
    const aiCount = allScans.filter((s) => s.isAiGenerated === true).length
    const safeCount = totalScans - spamCount

    const avgSpamScore =
      totalScans > 0
        ? Math.round(allScans.reduce((a, s) => a + (s.spamScore ?? 0), 0) / totalScans)
        : 0
    const avgAiConfidence =
      totalScans > 0
        ? Math.round(
            allScans
              .filter((s) => s.aiConfidence !== null)
              .reduce((a, s) => a + (s.aiConfidence ?? 0), 0) /
              Math.max(allScans.filter((s) => s.aiConfidence !== null).length, 1)
          )
        : 0

    const threatDist: Record<string, number> = {}
    for (const s of allScans) {
      const t = s.threatType || 'none'
      threatDist[t] = (threatDist[t] || 0) + 1
    }

    const sourceDist: Record<string, number> = {}
    for (const s of allScans) {
      sourceDist[s.source] = (sourceDist[s.source] || 0) + 1
    }

    const scoreBuckets = [0, 0, 0, 0, 0]
    for (const s of allScans) {
      const score = s.spamScore ?? 0
      if (score < 20) scoreBuckets[0]++
      else if (score < 40) scoreBuckets[1]++
      else if (score < 60) scoreBuckets[2]++
      else if (score < 80) scoreBuckets[3]++
      else scoreBuckets[4]++
    }

    const now = new Date()
    const last7Days: { date: string; count: number; spam: number }[] = []
    for (let i = 6; i >= 0; i--) {
      const day = new Date(now)
      day.setDate(day.getDate() - i)
      day.setHours(0, 0, 0, 0)
      const nextDay = new Date(day)
      nextDay.setDate(nextDay.getDate() + 1)
      const dayStr = day.toLocaleDateString('es-CL', {
        weekday: 'short',
        day: 'numeric',
        month: 'short',
      })
      const dayScans = allScans.filter((s) => {
        const d = new Date(s.createdAt)
        return d >= day && d < nextDay
      })
      last7Days.push({
        date: dayStr,
        count: dayScans.length,
        spam: dayScans.filter((s) => s.isSpam === true).length,
      })
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
      .slice(0, 5)

    return NextResponse.json({
      totalScans,
      spamCount,
      aiCount,
      safeCount,
      spamRate: totalScans > 0 ? Math.round((spamCount / totalScans) * 100) : 0,
      aiRate: totalScans > 0 ? Math.round((aiCount / totalScans) * 100) : 0,
      avgSpamScore,
      avgAiConfidence,
      threatDist,
      sourceDist,
      scoreBuckets,
      last7Days,
      topSenders,
      aiInsights: '',
    })
  } catch (error) {
    console.error('Error loading dashboard:', error)
    return NextResponse.json({ error: 'Error al cargar el dashboard' }, { status: 500 })
  }
}
