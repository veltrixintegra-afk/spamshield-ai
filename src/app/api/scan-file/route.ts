import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { analyzeEmail } from '@/lib/analyzer'

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File | null

    if (!file) {
      return NextResponse.json(
        { error: 'No se proporcionó ningún archivo' },
        { status: 400 }
      )
    }

    const allowedTypes = ['.eml', '.pst', '.msg', '.txt']
    const fileName = file.name.toLowerCase()
    const ext = '.' + fileName.split('.').pop()
    if (!allowedTypes.includes(ext)) {
      return NextResponse.json(
        { error: 'Formato de archivo no soportado. Usa: .eml, .pst, .msg, .txt' },
        { status: 400 }
      )
    }

    if (file.size > 25 * 1024 * 1024) {
      return NextResponse.json(
        { error: 'El archivo excede el límite de 25MB' },
        { status: 400 }
      )
    }

    const buffer = Buffer.from(await file.arrayBuffer())
    let fileContent: string

    if (ext === '.pst') {
      // For PST files, extract readable text content
      fileContent = extractTextFromBinary(buffer)
    } else {
      try {
        fileContent = new TextDecoder('utf-8', { fatal: false }).decode(buffer)
      } catch {
        fileContent = extractTextFromBinary(buffer)
      }
    }

    if (!fileContent.trim()) {
      return NextResponse.json(
        { error: 'No se pudo extraer contenido del archivo' },
        { status: 400 }
      )
    }

    const maxContentLength = 30000
    const truncatedContent = fileContent.length > maxContentLength
      ? fileContent.substring(0, maxContentLength) + '\n\n[... Contenido truncado por límite de longitud ...]'
      : fileContent

    // ── Análisis con motor propio ──
    const analysis = analyzeEmail({ content: truncatedContent })

    const fromMatch = fileContent.match(/From:\s*[^<]*<([^>]+)>/i) || fileContent.match(/From:\s*(\S+@\S+)/i)
    const subjectMatch = fileContent.match(/Subject:\s*(.+)/i)

    const savedScan = await db.emailScan.create({
      data: {
        source: 'upload',
        fileName: file.name,
        senderEmail: fromMatch?.[1]?.trim() || null,
        senderName: fromMatch?.[1]?.trim()?.split('<')?.[0]?.trim() || null,
        subject: subjectMatch?.[1]?.trim() || null,
        emailBody: truncatedContent,
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
    console.error('Error scanning file:', error)
    return NextResponse.json(
      { error: 'Error al analizar el archivo' },
      { status: 500 }
    )
  }
}

function extractTextFromBinary(buffer: Buffer): string {
  const str = buffer.toString('binary')
  const readable = str.replace(/[\x00-\x08\x0E-\x1F\x80-\xFF]/g, ' ')
  const lines = readable.split(/[\r\n]+/).filter((line: string) => {
    const trimmed = line.trim()
    return trimmed.length > 3 && /[a-zA-ZáéíóúñÁÉÍÓÚÑ@.]/.test(trimmed)
  })
  return lines.slice(0, 500).join('\n')
}
