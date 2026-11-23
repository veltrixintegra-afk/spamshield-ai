import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

// Politica de retencion: 90 dias (Ley 21.719 sobre Proteccion de Datos Personales)
const RETENTION_DAYS = 90
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000

/**
 * GET /api/retention
 * Retorna la politica de retencion y el conteo de analisis que seran
 * eliminados automaticamente al cumplir los 90 dias.
 */
export async function GET() {
  try {
    const cutoff = new Date(Date.now() - RETENTION_MS)

    // Total de registros almacenados
    const totalScans = await db.emailScan.count()

    // Registros que ya superaron los 90 dias (candidatos a eliminacion)
    const expiredScans = await db.emailScan.count({
      where: { createdAt: { lt: cutoff } },
    })

    // Registros que seran eliminados en los proximos 7 dias (aviso previo)
    const soonToDeleteCutoff = new Date(
      Date.now() - (RETENTION_DAYS - 7) * 24 * 60 * 60 * 1000
    )
    const soonToDelete = await db.emailScan.count({
      where: {
        createdAt: { lt: soonToDeleteCutoff, gte: cutoff },
      },
    })

    // Fecha limite del registro mas antiguo aun vigente
    const oldestScan = await db.emailScan.findFirst({
      orderBy: { createdAt: 'asc' },
      select: { createdAt: true },
    })

    return NextResponse.json({
      policy: {
        retentionDays: RETENTION_DAYS,
        legalBasis: 'Ley 21.719 sobre Protección de Datos Personales',
        description:
          'Los análisis de correos electrónicos se conservan por 90 días contados desde su fecha de creación, tras los cuales son eliminados automáticamente de forma permanente.',
        automaticDeletion: true,
      },
      stats: {
        totalScans,
        expiredScans,
        soonToDelete,
        oldestScanDate: oldestScan?.createdAt.toISOString() ?? null,
        cutoffDate: cutoff.toISOString(),
      },
    })
  } catch (error) {
    console.error('Error obteniendo política de retención:', error)
    return NextResponse.json(
      { error: 'Error al obtener la política de retención' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/retention
 * Ejecuta la limpieza automatica: elimina todos los analisis con mas de
 * 90 dias de antiguedad. Operacion irreversible (Ley 21.719).
 */
export async function DELETE() {
  try {
    const cutoff = new Date(Date.now() - RETENTION_MS)

    const result = await db.emailScan.deleteMany({
      where: { createdAt: { lt: cutoff } },
    })

    return NextResponse.json({
      success: true,
      deletedCount: result.count,
      cutoffDate: cutoff.toISOString(),
      message: `Se eliminaron ${result.count} análisis con más de ${RETENTION_DAYS} días de antigüedad.`,
    })
  } catch (error) {
    console.error('Error ejecutando limpieza de retención:', error)
    return NextResponse.json(
      { error: 'Error al ejecutar la limpieza de retención' },
      { status: 500 }
    )
  }
}
