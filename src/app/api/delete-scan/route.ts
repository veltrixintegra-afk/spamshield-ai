import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

/**
 * DELETE /api/delete-scan
 * Elimina permanentemente un analisis especifico por su ID.
 * Operacion irreversible amparada en el derecho de cancelacion (ARCO)
 * establecido en la Ley 21.719 sobre Proteccion de Datos Personales.
 *
 * Body: { "scanId": "string" }
 */
export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json()
    const { scanId } = body

    if (!scanId || typeof scanId !== 'string') {
      return NextResponse.json(
        { error: 'ID de análisis requerido' },
        { status: 400 }
      )
    }

    // Verificar que el registro existe antes de eliminar
    const existing = await db.emailScan.findUnique({
      where: { id: scanId },
      select: { id: true },
    })

    if (!existing) {
      return NextResponse.json(
        { error: 'El análisis no existe o ya fue eliminado' },
        { status: 404 }
      )
    }

    await db.emailScan.delete({
      where: { id: scanId },
    })

    return NextResponse.json({
      success: true,
      message: 'Análisis eliminado permanentemente.',
    })
  } catch (error) {
    console.error('Error eliminando análisis:', error)
    return NextResponse.json(
      { error: 'Error al eliminar el análisis' },
      { status: 500 }
    )
  }
}
