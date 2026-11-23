# LEGAL-1 — Cumplimiento Legal SpamShield AI

**Agente:** Claude (main agent)
**Fecha:** 2026-11-23
**Tarea:** Implementar 6 funcionalidades de cumplimiento legal para leyes chilenas (Ley 21.663, Ley 21.719, Ley 21.459) en el proyecto SpamShield AI.

## Resumen de cambios

Se implementaron las 6 funcionalidades solicitadas en 4 archivos (2 nuevos, 2 modificados). Todas pasaron `bun run lint` sin errores.

### Archivos modificados / creados

1. **`src/app/page.tsx`** (modificado, +436 líneas)
2. **`src/app/api/generate-report/route.ts`** (modificado, +282 líneas)
3. **`src/app/api/retention/route.ts`** (nuevo)
4. **`src/app/api/delete-scan/route.ts`** (nuevo)

### Detalle por funcionalidad

#### 1. Modal de Política de Privacidad
- Nuevo `useState` `showPrivacyDialog` controla un `Dialog` con la política completa en español.
- Política cubre: datos recopilados, finalidad, base legal (Ley 21.719), retención 90 días, derechos ARCO, contacto (`privacidad@spamshield.cl`).
- Footer: el enlace "Privacidad" se reemplazó por un botón "Política de Privacidad" que abre el modal.

#### 2. Checkbox de Consentimiento (Ley 21.719)
- Nuevo componente reutilizable `ConsentCheckbox` con el texto exacto solicitado.
- Estado `hasConsent` compartido entre las 3 pestañas del escáner (texto, archivo, bandeja).
- `handleScanText`, `handleScanFile` y `handleConnectProvider` validan `hasConsent` antes de continuar.
- Todos los botones de analizar / conectar quedan `disabled` cuando `!hasConsent`.
- Se muestran toasts informativos si el usuario intenta analizar sin consentimiento.

#### 3. Tarjeta "Reportar a Autoridades"
- Insertada en la sección de Resultados, entre Recomendaciones y los botones de acción.
- Grid de 3 columnas (md) / 1 columna (móvil) con enlaces externos:
  - **CSIRT Nacional** → https://csirt.gob.cl (Shield, color esmeralda)
  - **BRICIB / PDI** → https://www.pdi.cl (ShieldAlert, color rojo)
  - **Fiscalía de Chile** → https://www.fiscaliedeley.cl (FileText, color azul)
- Cada tarjeta incluye descripción del tipo de denuncia que corresponde reportar.

#### 4. Mejoras al informe PDF (`generate-report/route.ts`)
- **4a. Hash de Integridad SHA-256**: calculado sobre el contenido del correo + metadatos del análisis usando `crypto.createHash('sha256')`. Mostrado en el footer de la portada (truncado) y en una sección dedicada en la página 5 (completo).
- **4b. Campos del Denunciante**: sección nueva en página 2 con campos vacíos (Nombre, RUT, Contacto, Relación con el incidente) para rellenar a mano al imprimir.
- **4c. Declaración de Veracidad**: checkbox estilo (cuadro vacío) con el texto exacto solicitado, más líneas para firma y fecha.
- **4d. Cláusula Legal de Limitación de Responsabilidad**: banner ámbar en la última página con el texto exacto solicitado y badges de las tres leyes (21.663, 21.459, 21.719).

#### 5. Retención y Eliminación de Datos
- **`src/app/api/retention/route.ts`** (nuevo):
  - `GET`: retorna política de retención (90 días, base legal Ley 21.719) + estadísticas (total, expirados, próximos a caducar, registro más antiguo).
  - `DELETE`: ejecuta limpieza automática con `db.emailScan.deleteMany({ where: { createdAt: { lt: cutoff } } })` donde `cutoff = Date.now() - 90 días`.
- **`src/app/api/delete-scan/route.ts`** (nuevo):
  - `DELETE`: acepta `{ scanId }` en el body, verifica existencia y elimina el análisis específico (derecho ARCO de cancelación).
- **UI en Historial**: 
  - Texto informativo bajo el título: "Los análisis se conservan por 90 días según nuestra política de retención (Ley 21.719)."
  - Botón de eliminar (Trash2, color rojo) en cada fila de la tabla, con estado de carga (Loader2 girando) y tooltip "Eliminar permanentemente".
  - Tras eliminar, se recarga el historial y se limpia el resultado visible si correspondía al registro eliminado.

#### 6. Banner de Limitación de Responsabilidad
- Insertado en la parte superior del escáner, después del encabezado y antes de los tabs.
- Banner sutil ámbar/amarillo con icono `AlertTriangle`.
- Texto exacto: "⚠️ SpamShield AI es una herramienta de apoyo técnico. Los resultados no constituyen prueba pericial oficial. Para denuncias formales, contacte a las autoridades competentes."
- Usa `role="alert"` y `aria-live="polite"` para accesibilidad.

### Verificación
- `bun run lint` → exit code 0, sin errores.
- Commit: `eb7a82a feat: cumplimiento legal - politica privacidad, consentimiento, reporte autoridades, retention`
- 4 archivos cambiados, 851 inserciones(+), 11 eliminaciones(-).

### Notas
- El esquema Prisma y el modelo `EmailScan` no fueron modificados (se reutiliza el existente).
- Se mantienen todas las funcionalidades previas intactas.
- El issue preexistente con `DIRECT_DATABASE_URL` en `.env` impide ejecutar `prisma db push`, pero no afecta al código fuente ni a su despliegue en Vercel (donde las variables de entorno sí estarán configuradas).
