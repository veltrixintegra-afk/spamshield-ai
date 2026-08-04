import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET() {
  try {
    const scans = await db.emailScan.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        id: true,
        source: true,
        fileName: true,
        senderEmail: true,
        senderName: true,
        subject: true,
        isSpam: true,
        spamScore: true,
        aiConfidence: true,
        isAiGenerated: true,
        threatType: true,
        createdAt: true,
      },
    })

    const formatted = scans.map((s) => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
    }))

    return NextResponse.json(formatted)
  } catch (error) {
    console.error('Error loading history:', error)
    return NextResponse.json(
      { error: 'Error al cargar el historial' },
      { status: 500 }
    )
  }
}

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url)
    const id = searchParams.get('id')
    if (!id) {
      return NextResponse.json({ error: 'ID requerido' }, { status: 400 })
    }
    await db.emailScan.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting scan:', error)
    return NextResponse.json(
      { error: 'Error al eliminar el registro' },
      { status: 500 }
    )
  }
}
