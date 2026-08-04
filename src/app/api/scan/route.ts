import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import ZAI from 'z-ai-web-dev-sdk'

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

    const zai = await ZAI.create()

    const systemPrompt = `Eres un analista forense de correo electrónico experto en ciberseguridad con más de 15 años de experiencia. Tu especialidad es detectar correos spam, phishing, estafas tipo "voiceship" (suplantación de voz/CEO), spoofing, malware y técnicas de ingeniería social. También eres experto en detectar si un correo fue generado por inteligencia artificial.

Analiza profundamente el correo proporcionado y devuelve ÚNICAMENTE un JSON válido con esta estructura exacta (sin markdown, sin backticks, sin texto adicional):
{
  "isSpam": true/false,
  "spamScore": 0-100,
  "isAiGenerated": true/false,
  "aiConfidence": 0-100,
  "threatType": "phishing" | "voiceship" | "spoofing" | "malware" | "social_engineering" | "none",
  "senderAnalysis": "Análisis detallado del remitente en español, incluyendo si el dominio es sospechoso, si hay coincidencias con remitentes conocidos de spam, y si la dirección de correo sigue patrones de suplantación",
  "summary": "Resumen ejecutivo del análisis en español, 3-5 oraciones",
  "detailedAnalysis": "Análisis forense detallado en markdown en español. Incluye: indicadores técnicos encontrados, evaluación de URLs/enlaces, análisis del lenguaje usado, patrones de ingeniería social detectados, y evaluación de si el contenido muestra señales de haber sido generado por IA (fórmulas repetitivas, falta de personalización, estructura demasiado perfecta)",
  "recommendations": "Recomendaciones de seguridad detalladas en markdown en español, incluyendo acciones inmediatas y preventivas"
}

Criterios de evaluación específicos:
1. INDICADORES DE SPAM: urgencia artificial, presión psicológica, solicitudes de datos personales/financieros, ofertas demasiado buenas, errores gramaticales intencionales
2. PATRONES VOICESHIP/CEO: suplantación de autoridad, solicitudes de transferencias urgentes, tono imperativo fingiendo ser un superior
3. PHISHING: URLs que no coinciden con el dominio legítimo, formularios para capturar credenciales, certificados SSL falsos
4. IA GENERADA: lenguaje excesivamente pulido sin errores, estructura demasiado uniforme, falta de contexto personal específico, frases genéricas que podrían aplicarse a cualquier destinatario, uso de fórmulas de cortesía estereotipadas
5. SPOOFING: dominio del remitente similar pero no idéntico al legítimo, headers manipulados
6. INGENIERÍA SOCIAL: creación de escenarios emocionales, falsa familiaridad, autoridad falsa

Responde SOLO el JSON, nada más.`

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'assistant', content: systemPrompt },
        { role: 'user', content: emailContent },
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
        throw new Error('No JSON found in response')
      }
    } catch {
      analysis = {
        isSpam: false,
        spamScore: 15,
        isAiGenerated: false,
        aiConfidence: 10,
        threatType: 'none',
        senderAnalysis: 'No se pudo determinar el análisis completo del remitente.',
        summary: 'El análisis no pudo completarse completamente. El correo fue procesado parcialmente.',
        detailedAnalysis: '## Análisis Incompleto\n\nNo se pudo obtener un análisis detallado completo del correo electrónico. Por favor, intenta de nuevo con más contenido del correo.',
        recommendations: '## Recomendaciones\n\n- Intentar analizar el correo nuevamente\n- Verificar manualmente los enlaces y remitente\n- No interactuar con enlaces sospechosos',
      }
    }

    const fromMatch = emailContent.match(/From:\s*(.+)/i)
    const subjectMatch = emailContent.match(/Subject:\s*(.+)/i)

    const savedScan = await db.emailScan.create({
      data: {
        source: 'paste',
        senderEmail: fromMatch?.[1]?.trim() || null,
        senderName: fromMatch?.[1]?.trim()?.split('<')?.[0]?.trim() || null,
        subject: subjectMatch?.[1]?.trim() || null,
        emailBody: emailContent.substring(0, 10000),
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
    console.error('Error scanning email:', error)
    return NextResponse.json(
      { error: 'Error al analizar el correo electrónico' },
      { status: 500 }
    )
  }
}
