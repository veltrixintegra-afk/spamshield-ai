import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { analyzeEmail } from '@/lib/analyzer'

export async function POST(request: NextRequest) {
  try {
    const { emailContent } = await request.json()

    if (!emailContent || typeof emailContent !== 'string') {
      return NextResponse.json(
        { error: 'Contenido del correo es requerido' },
        { status: 400 }
      )
    }

    if (emailContent.length > 500000) {
      return NextResponse.json(
        { error: 'El contenido excede el límite permitido' },
        { status: 400 }
      )
    }

    // ── Análisis con motor propio ──
    const analysis = analyzeEmail({ content: emailContent })

    // Extraer remitente y asunto del contenido
    const fromMatch = emailContent.match(/From:\s*[^<]*<([^>]+)>/i) || emailContent.match(/From:\s*(\S+@\S+)/i)
    const subjectMatch = emailContent.match(/Subject:\s*(.+)/i)

    const savedScan = await db.emailScan.create({
      data: {
        source: 'paste',
        senderEmail: fromMatch?.[1]?.trim() || null,
        senderName: fromMatch?.[1]?.trim()?.split('<')?.[0]?.trim() || null,
        subject: subjectMatch?.[1]?.trim() || null,
        emailBody: emailContent.substring(0, 10000),
        isSpam: analysis.isSpam,
        spamScore: analysis.spamScore,
        isAiGenerated: analysis.isAiGenerated,
        aiConfidence: analysis.aiConfidence,
        threatType: analysis.threatType,
        analysisJson: JSON.stringify(analysis),
      },
    })

    return NextResponse.json({
      id: savedScan.id,
      ...analysis,
    })
  } catch (error) {
    console.error('Error scanning email:', error)
    return NextResponse.json(
      { error: 'Error al analizar el correo electrónico' },
      { status: 500 }
    )
  }
}
