import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import ZAI from 'z-ai-web-dev-sdk'
import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import os from 'os'

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

    const zai = await ZAI.create()

    const systemPrompt = `Eres un analista forense de correo electrónico experto en ciberseguridad con más de 15 años de experiencia. Tu especialidad es detectar correos spam, phishing, estafas tipo "voiceship" (suplantación de voz/CEO), spoofing, malware y técnicas de ingeniería social. También eres experto en detectar si un correo fue generado por inteligencia artificial.

Analiza profundamente el correo proporcionado y devuelve ÚNICAMENTE un JSON válido con esta estructura exacta (sin markdown, sin backticks, sin texto adicional):
{
  "isSpam": true/false,
  "spamScore": 0-100,
  "isAiGenerated": true/false,
  "aiConfidence": 0-100,
  "threatType": "phishing" | "voiceship" | "spoofing" | "malware" | "social_engineering" | "none",
  "senderAnalysis": "Análisis detallado del remitente en español",
  "summary": "Resumen ejecutivo del análisis en español, 3-5 oraciones",
  "detailedAnalysis": "Análisis forense detallado en markdown en español",
  "recommendations": "Recomendaciones de seguridad detalladas en markdown en español"
}

Evalúa indicadores de spam, phishing, voiceship, spoofing, malware, ingeniería social y señales de contenido generado por IA.
Responde SOLO el JSON, nada más.`

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'assistant', content: systemPrompt },
        { role: 'user', content: `[Archivo: ${file.name}](Tipo: ${ext})\n\n${truncatedContent}` },
      ],
      thinking: { type: 'disabled' },
    })

    const responseText = completion.choices?.[0]?.message?.content || ''

    let analysis: Record<string, any>
    try {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/)
      if (jsonMatch) {
        analysis = JSON.parse(jsonMatch[0])
      } else {
        throw new Error('No JSON found')
      }
    } catch {
      analysis = {
        isSpam: false,
        spamScore: 15,
        isAiGenerated: false,
        aiConfidence: 10,
        threatType: 'none',
        senderAnalysis: 'No se pudo determinar el análisis completo del remitente.',
        summary: 'El análisis del archivo no pudo completarse completamente.',
        detailedAnalysis: '## Análisis Incompleto\n\nNo se pudo obtener un análisis detallado del archivo de correo.',
        recommendations: '## Recomendaciones\n\n- Intentar analizar el archivo nuevamente\n- Verificar manualmente los enlaces y remitente',
      }
    }

    const fromMatch = fileContent.match(/From:\s*(.+)/i)
    const subjectMatch = fileContent.match(/Subject:\s*(.+)/i)

    const savedScan = await db.emailScan.create({
      data: {
        source: 'upload',
        fileName: file.name,
        senderEmail: fromMatch?.[1]?.trim() || null,
        senderName: fromMatch?.[1]?.trim()?.split('<')?.[0]?.trim() || null,
        subject: subjectMatch?.[1]?.trim() || null,
        emailBody: truncatedContent,
        isSpam: analysis.isSpam ?? false,
        spamScore: analysis.spamScore ?? 0,
        isAiGenerated: analysis.isAiGenerated ?? false,
        aiConfidence: analysis.aiConfidence ?? 0,
        threatType: analysis.threatType || 'none',
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
  const textParts: string[] = []
  const str = buffer.toString('binary')
  // Extract readable ASCII/UTF-8 sequences
  const readable = str.replace(/[\x00-\x08\x0E-\x1F\x80-\xFF]/g, ' ')
  const lines = readable.split(/[\r\n]+/).filter((line: string) => {
    const trimmed = line.trim()
    return trimmed.length > 3 && /[a-zA-ZáéíóúñÁÉÍÓÚÑ@.]/.test(trimmed)
  })
  return lines.slice(0, 500).join('\n')
}
