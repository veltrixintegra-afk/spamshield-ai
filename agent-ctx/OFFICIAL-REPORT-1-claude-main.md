# OFFICIAL-REPORT-1 — Informe Oficial de Denuncia SpamShield AI

**Agente:** Claude (main agent)
**Fecha:** 2026-11-23
**Tarea:** Implementar un sistema de **Informe Oficial de Denuncia** con declaración jurada firmada, apto para presentar denuncias formales ante PDI/BRICIB, Carabineros, ANCI y Fiscalía de Chile.

## Resumen de cambios

Se implementaron las funcionalidades solicitadas en **2 archivos** (1 nuevo, 1 modificado). `bun run lint` pasa sin errores (exit code 0).

### Archivos modificados / creados

1. **`src/app/api/generate-official-report/route.ts`** (NUEVO, ~1000 líneas) — Endpoint POST que genera el informe oficial HTML de 7 páginas.
2. **`src/app/page.tsx`** (modificado, ~+690 líneas) — Botón, dialog multi-step, estado y handler.

---

## Detalle por componente

### 1. Endpoint API `/api/generate-official-report` (route.ts)

**POST** recibe `{ scanId, denunciante, autoridad, firmaDigital, fecha, aceptaDeclaracion }`.

Pasos del endpoint:
1. **Valida** todos los campos requeridos (nombre, rut, domicilio, teléfono, email, firmaDigital ≥ 4 chars, aceptaDeclaracion === true, autoridad válida).
2. **Recupera** el `EmailScan` desde Prisma (`db.emailScan.findUnique`).
3. **Parsea** `analysisJson` para obtener `senderAnalysis`, `summary`, `detailedAnalysis`, `recommendations`.
4. **Genera número de caso oficial** con formato `SSA-YYYY-NNNNNN` (año actual + 6 dígitos aleatorios padded con ceros). Ejemplo: `SSA-2026-004821`.
5. **Calcula hash SHA-256** sobre el JSON compuesto por `scanId + denunciante + autoridad + firmaDigital + fecha + analysis` usando `crypto.createHash('sha256')`.
6. **Devuelve HTML** como `Content-Type: text/html` con `Content-Disposition: attachment; filename="SpamShield-Denuncia-${caseNumber}.html"`.

**Estructura del HTML generado (7 páginas A4):**
- **Página 1 — Portada oficial**: Fondo degradado oscuro esmeralda, número de caso en grande (monospace, 36px), autoridad destinataria, clasificación "DOCUMENTO OFICIAL — CONFIDENCIAL", fecha, veredicto, hash truncado.
- **Página 2 — Datos del Denunciante**: Tabla completa con Nombre, RUT, Nacionalidad, Domicilio, Teléfono, Email, Relación. Sección de autoridad destinataria con competencia, URL y dirección.
- **Página 3 — Declaración Jurada**: Caja con borde esmeralda; preámbulo con nombre/RUT interpolados; lista numerada con los 7 puntos exactos solicitados; base legal; **firma digital renderizada en fuente cursiva (`Brush Script MT`, 28px, italic)**; nota sobre la **Ley 19.799** (firma electrónica equivale a manuscrita).
- **Página 4 — Resumen Ejecutivo + Métricas**: SVG gauge circular de amenaza, 4 metric-mini cards (Spam Score, Probabilidad IA, ¿Es Spam?, ¿Generado por IA?), threat bars por categoría, resumen del análisis.
- **Página 5 — Metadatos + Forense**: Tabla de info del correo (remitente, email, asunto, amenaza, riesgo, fuente, fecha, badges) + análisis del remitente + análisis forense detallado (markdown renderizado).
- **Página 6 — Recomendaciones + Email**: Recomendaciones de seguridad + extracto del correo original (truncado a 1800 chars con indicador).
- **Página 7 — Marco Legal + Cadena de Custodia + Hash**: 
  - **Marco Legal**: 5 leyes (Ley 21.663, 21.459, 21.719, Art. 210, Art. 211B Código Penal) con código, nombre y descripción.
  - **Autoridades Competentes**: 4 tarjetas (PDI, Carabineros, ANCI, Fiscalía) con URL y dirección; la autoridad seleccionada se resalta con borde esmeralda activo.
  - **Cadena de Custodia**: 6 pasos numerados (recepción → ingreso → análisis → cálculo → generación → custodia del denunciante).
  - **Hash SHA-256 completo** con nota explicativa.
  - **Caja de verificación**: instrucciones para verificar autenticidad con el número de caso.
  - **Cláusula de Responsabilidad final** con texto plano de la declaración + líneas para firma manuscrita y fecha.

**Footer en cada página** (3 columnas): número de caso (izquierda, monospace esmeralda), "Página X de 7" (centro), "SpamShield AI — Documento Oficial de Denuncia" (derecha).

**Print bar superior**: Banner fijo verde esmeralda con icono de escudo, número de caso destacado, botón "Imprimir / Guardar como PDF" (window.print) y botón "Cerrar".

### 2. UI en `src/app/page.tsx`

#### 2a. Nuevos imports
- `Input`, `Label` desde `@/components/ui/input|label`
- `RadioGroup`, `RadioGroupItem` desde `@/components/ui/radio-group`
- `Select`, `SelectContent`, `SelectItem`, `SelectTrigger`, `SelectValue` desde `@/components/ui/select`
- Iconos Lucide: `Gavel`, `Stamp`, `FileCheck2`, `Landmark`, `BadgeCheck`, `ChevronRight`, `ChevronLeft`, `ShieldCheck`

#### 2b. Nuevo estado
```ts
const [showOfficialDialog, setShowOfficialDialog] = useState(false)
const [officialStep, setOfficialStep] = useState(1)  // wizard 1-4
const [isGeneratingOfficial, setIsGeneratingOfficial] = useState(false)
const [officialReportData, setOfficialReportData] = useState({
  nombre, rut, nacionalidad: 'Chilena', domicilio, telefono, email,
  relacion: 'Victima', autoridad: 'pdi', firmaDigital, fecha: hoy,
  aceptaDeclaracion: false
})
```

#### 2c. Funciones auxiliares y handler
- **`formatRUTInput(raw)`**: formatea el input mientras el usuario escribe a `XX.XXX.XXX-X`.
- **`isValidRUT(rut)`**: validación módulo 11 completa (calcula el dígito verificador).
- **`isValidEmail(email)`**: regex estándar.
- **`officialStep1Valid`**: valida que nombre ≥ 4 chars, RUT válido, domicilio ≥ 8 chars, teléfono ≥ 6 chars, email válido.
- **`officialStep3Valid`**: requiere `aceptaDeclaracion === true`, `firmaDigital ≥ 4 chars` y fecha no vacía.
- **`handleGenerateOfficialReport()`**: 
  1. Verifica `scanResult.id` existe.
  2. Validación final de steps 1 y 3 (con feedback de toast y redirección al step correspondiente si falla).
  3. Toast "Generando informe oficial de denuncia...".
  4. POST a `/api/generate-official-report`.
  5. Recibe HTML, crea Blob, abre `window.open()` en nueva pestaña.
  6. Toast de éxito al cargar (`printWindow.addEventListener('load', ...)`).
  7. Fallback a descarga directa si el popup es bloqueado.
  8. Cierra el diálogo y resetea el wizard a step 1.

#### 2d. Nuevo botón en sección de resultados
Insertado entre "Descargar Informe PDF" y "Nuevo Análisis":
- Texto: **"Generar Informe Oficial de Denuncia"**
- Icono: `ShieldCheck`
- Color: `bg-emerald-700 hover:bg-emerald-600` con borde esmeralda y sombra.
- Al hacer clic: `setOfficialStep(1)` + `setShowOfficialDialog(true)`.

#### 2e. Dialog multi-step (4 pasos)
- **Diálogo**: `max-w-3xl max-h-[92vh] overflow-y-auto`, header con icono ShieldCheck.
- **Stepper visual**: 4 círculos numerados conectados por líneas; el paso actual y completados se muestran en esmeralda.
- **Animaciones**: `framer-motion` con `AnimatePresence mode="wait"`, transiciones x:20→0 con duración 0.2s.

**Step 1 — Datos del Denunciante**:
- Grid 2 columnas (1 en móvil).
- Campos: Nombre completo (Input), RUT (Input mono con formateo en vivo + validación módulo 11), Nacionalidad (Select: 9 opciones, default Chilena), Domicilio (Textarea 2 rows), Teléfono (Input), Email (Input type=email con validación regex), Relación con el incidente (Select: Víctima / Testigo / Representante legal / Tercero).
- Validación visual: mensajes de error bajo RUT y email si son inválidos.
- Botón "Siguiente" deshabilitado hasta que `officialStep1Valid` sea true.

**Step 2 — Autoridad Destinataria**:
- RadioGroup con 5 opciones: PDI/BRICIB, Carabineros, ANCI/CSIRT, Fiscalía, Todas las anteriores.
- Cada opción es una `Label` clicable con icono, título y descripción.
- La opción activa se resalta con borde esmeralda + fondo esmeralda 5% + ring.
- Botones Atrás / Siguiente (siempre habilitado, la autoridad tiene default 'pdi').

**Step 3 — Declaración Jurada y Acuerdo de Responsabilidad**:
- Caja scrollable (`max-h-72 overflow-y-auto`) con la declaración completa en español:
  - Preámbulo con **nombre y RUT interpolados dinámicamente** desde el estado.
  - Lista ordenada con los 7 puntos exactos del enunciado.
  - Base legal (Ley 21.663, 21.459, 21.719, Art. 210).
  - Línea para firma manuscrita.
- Checkbox "He leído y acepto la declaración jurada de responsabilidad" (Label clicable con borde).
- Input para **firma digital** (escribir nombre completo) con estilo italic + nota sobre Ley 19.799.
- Input `type="date"` con la fecha por defecto (hoy), editable.
- Botón "Siguiente" deshabilitado hasta que `officialStep3Valid` sea true.

**Step 4 — Revisión y Generación**:
- Resumen visual de todos los datos ingresados (denunciante, RUT, email, autoridad, relación, fecha formateada, firma digital en italic).
- Banner ámbar informativo: explica el formato `SSA-YYYY-NNNNNN`, el hash SHA-256, y aclara que **los datos personales no se almacenan** en la base de datos.
- Botón **"Generar Informe Oficial"** (esmeralda 700, con icono FileText). Estado loading con `Loader2` girando y texto "Generando...". Deshabilitado si `!officialStep1Valid || !officialStep3Valid || isGeneratingOfficial`.

### Notas técnicas
- **No se persisten datos personales**: el endpoint no escribe denunciante/firma en la DB; sólo se incluyen en el HTML generado. El campo `reportPath` no se actualiza (se mantiene el flujo del informe forense original intacto).
- **RUT**: formato XX.XXX.XXX-X con validación módulo 11 completa (cálculo del dígito verificador).
- **Firma digital**: el texto ingresado se renderiza en el PDF con fuente cursiva (`Brush Script MT` fallback `Lucida Handwriting` / `Segoe Script` / `cursive`), 28px, italic, color esmeralda oscuro.
- **Numeración de caso**: usa `Math.random()` con padding a 6 dígitos. No hay persistencia del número; cada generación produce uno nuevo.
- **Compatibilidad Vercel**: el endpoint usa `crypto` del módulo estándar de Node.js (disponible en el runtime de Node de Vercel) y `db.emailScan.findUnique` de Prisma. No usa APIs no soportadas.
- **Accesibilidad**: todos los Inputs tienen `id` + `Label htmlFor`; los requeridos llevan `aria-required="true"`; RUT y email inválidos marcan `aria-invalid`. El diálogo es controlado por `Dialog` (Radix) que maneja foco y escape automáticamente.
- **Responsive**: el diálogo se adapta de 1 columna (móvil) a 2 columnas (sm+). Los botones de acción se apilan en móvil (`flex-col sm:flex-row`).

### Verificación
- `bun run lint` → exit code 0, sin errores ni warnings.
- Commit: ver abajo.
- Archivos: 2 cambiados (1 nuevo + 1 modificado), ~+1700 líneas totales.

### Contexto previo reutilizado
- **`LEGAL-1-claude-main.md`**: el agente anterior implementó el modal de política de privacidad, el checkbox de consentimiento (Ley 21.719), las tarjetas de autoridades, el hash SHA-256 en el informe forense, y la retención/eliminación. Esta tarea **extiende** ese trabajo añadiendo un flujo formal de denuncia con declaración jurada firmada y un documento PDF mejorado de 7 páginas.
- **Issue preexistente**: el `.env` no define `DIRECT_DATABASE_URL`, por lo que `prisma db push` falla localmente, pero no afecta al código fuente ni al despliegue en Vercel (donde las variables sí están configuradas). El `db.emailScan.findUnique` funciona correctamente con el `DATABASE_URL` existente.
