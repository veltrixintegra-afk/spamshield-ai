'use client'

import React, { useState, useRef, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import { toast } from 'sonner'
import { useTheme } from 'next-themes'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Textarea } from '@/components/ui/textarea'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { Separator } from '@/components/ui/separator'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Shield,
  Upload,
  Mail,
  AlertTriangle,
  CheckCircle,
  XCircle,
  FileText,
  Download,
  History,
  Sun,
  Moon,
  Github,
  Globe,
  Scan,
  Brain,
  Zap,
  Lock,
  Eye,
  Clock,
  ArrowRight,
  Trash2,
  ChevronDown,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  FileUp,
  Inbox,
  Loader2,
  BarChart3,
  Bot,
  Phishing,
  UserX,
} from 'lucide-react'

/* ============================================================
   TYPES
   ============================================================ */

interface ScanResult {
  id: string
  isSpam: boolean
  spamScore: number
  isAiGenerated: boolean
  aiConfidence: number
  threatType: string
  senderAnalysis: string
  summary: string
  detailedAnalysis: string
  recommendations: string
}

interface HistoryEntry {
  id: string
  source: string
  senderEmail: string | null
  senderName: string | null
  subject: string | null
  isSpam: boolean | null
  spamScore: number | null
  threatType: string | null
  createdAt: string
}

/* ============================================================
   ANIMATION VARIANTS
   ============================================================ */

const fadeIn = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' } },
}

const slideUp = {
  hidden: { opacity: 0, y: 40 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: 'easeOut' } },
}

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.1 },
  },
}

const scaleIn = {
  hidden: { opacity: 0, scale: 0.8 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.4, ease: 'easeOut' } },
}

/* ============================================================
   HELPER: VERDICT COLOR & LABEL
   ============================================================ */

function getVerdictInfo(score: number): {
  label: string
  color: string
  bgColor: string
  borderColor: string
  icon: React.ReactNode
} {
  if (score < 30) {
    return {
      label: 'SEGURO',
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/30',
      icon: <CheckCircle className="size-5 text-emerald-400" />,
    }
  }
  if (score < 60) {
    return {
      label: 'SOSPECHOSO',
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30',
      icon: <AlertTriangle className="size-5 text-amber-400" />,
    }
  }
  if (score < 80) {
    return {
      label: 'PELIGROSO',
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30',
      icon: <ShieldAlert className="size-5 text-orange-400" />,
    }
  }
  return {
    label: 'CRÍTICO',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    icon: <ShieldX className="size-5 text-red-400" />,
  }
}

function getGaugeColor(score: number): string {
  if (score < 30) return '#10b981'
  if (score < 60) return '#f59e0b'
  if (score < 80) return '#f97316'
  return '#ef4444'
}

function getThreatTypeLabel(type: string): string {
  const map: Record<string, string> = {
    phishing: 'Phishing',
    voiceship: 'Estafa de Voz/CEO',
    spoofing: 'Spoofing',
    malware: 'Malware',
    social_engineering: 'Ingeniería Social',
    none: 'Sin Amenaza',
    unknown: 'Desconocido',
  }
  return map[type] || type
}

function getSourceLabel(source: string): string {
  const map: Record<string, string> = {
    paste: 'Texto Pegado',
    upload: 'Archivo Subido',
    gmail: 'Gmail',
    outlook: 'Outlook',
  }
  return map[source] || source
}

/* ============================================================
   COMPONENT: THREAT GAUGE (SVG Circle)
   ============================================================ */

function ThreatGauge({ score }: { score: number }) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const color = getGaugeColor(score)
  const verdict = getVerdictInfo(score)
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (animatedScore / 100) * circumference

  useEffect(() => {
    let start = 0
    const duration = 1500
    const startTime = Date.now()
    const animate = () => {
      const elapsed = Date.now() - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      start = Math.round(eased * score)
      setAnimatedScore(start)
      if (progress < 1) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [score])

  return (
    <div className="relative flex flex-col items-center gap-3">
      <div className="relative">
        <svg width="180" height="180" viewBox="0 0 180 180" className="transform -rotate-90">
          <circle
            cx="90"
            cy="90"
            r={radius}
            stroke="currentColor"
            strokeWidth="10"
            fill="none"
            className="text-muted/30"
          />
          <circle
            cx="90"
            cy="90"
            r={radius}
            stroke={color}
            strokeWidth="10"
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.3s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold" style={{ color }}>
            {animatedScore}
          </span>
          <span className="text-xs text-muted-foreground uppercase tracking-wider">
            / 100
          </span>
        </div>
      </div>
      <Badge
        variant="outline"
        className={`${verdict.bgColor} ${verdict.borderColor} ${verdict.color} border px-4 py-1.5 text-sm font-semibold`}
      >
        {verdict.icon}
        <span className="ml-1.5">{verdict.label}</span>
      </Badge>
    </div>
  )
}

/* ============================================================
   COMPONENT: LOADING SKELETON
   ============================================================ */

function AnalysisLoadingSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row gap-6">
        <Skeleton className="h-[220px] w-[220px] rounded-full mx-auto md:mx-0" />
        <div className="flex-1 space-y-4">
          <Skeleton className="h-8 w-48" />
          <div className="grid grid-cols-2 gap-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        </div>
      </div>
      <Separator />
      <div className="space-y-3">
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-5/6" />
      </div>
    </div>
  )
}

/* ============================================================
   MAIN PAGE COMPONENT
   ============================================================ */

export default function Home() {
  const { theme, setTheme } = useTheme()

  // ── State ──
  const [emailContent, setEmailContent] = useState('')
  const [activeTab, setActiveTab] = useState('texto')
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [showResults, setShowResults] = useState(false)
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [isLoadingHistory, setIsLoadingHistory] = useState(false)
  const [selectedHistoryEntry, setSelectedHistoryEntry] = useState<HistoryEntry | null>(null)
  const [showAnalysisDialog, setShowAnalysisDialog] = useState(false)
  const [expandedAnalysis, setExpandedAnalysis] = useState(false)

  // ── Refs ──
  const fileInputRef = useRef<HTMLInputElement>(null)

  // ── Load history on mount ──
  useEffect(() => {
    loadHistory()
  }, [])

  // ── API: Load History ──
  const loadHistory = async () => {
    setIsLoadingHistory(true)
    try {
      const res = await fetch('/api/history')
      if (!res.ok) throw new Error('Error al cargar historial')
      const data = await res.json()
      setHistory(data)
    } catch {
      toast.error('No se pudo cargar el historial de análisis')
    } finally {
      setIsLoadingHistory(false)
    }
  }

  // ── API: Scan Text ──
  const handleScanText = async () => {
    if (!emailContent.trim()) {
      toast.error('Por favor, ingresa el contenido del correo electrónico')
      return
    }

    setIsScanning(true)
    setShowResults(true)
    setScanResult(null)

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emailContent }),
      })

      if (!res.ok) throw new Error('Error en el análisis')

      const data: ScanResult = await res.json()
      setScanResult(data)
      toast.success('Análisis completado exitosamente')
      loadHistory()
    } catch {
      toast.error('Error al analizar el correo. Intenta de nuevo.')
      setShowResults(false)
    } finally {
      setIsScanning(false)
    }
  }

  // ── API: Scan File ──
  const handleScanFile = async () => {
    if (!uploadedFile) {
      toast.error('Por favor, selecciona un archivo para analizar')
      return
    }

    setIsScanning(true)
    setShowResults(true)
    setScanResult(null)

    try {
      const formData = new FormData()
      formData.append('file', uploadedFile)

      const res = await fetch('/api/scan-file', {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) throw new Error('Error en el análisis del archivo')

      const data: ScanResult = await res.json()
      setScanResult(data)
      toast.success('Archivo analizado exitosamente')
      loadHistory()
    } catch {
      toast.error('Error al analizar el archivo. Intenta de nuevo.')
      setShowResults(false)
    } finally {
      setIsScanning(false)
    }
  }

  // ── API: Generate PDF Report ──
  const handleGenerateReport = async () => {
    if (!scanResult?.id) {
      toast.error('No hay resultados para generar el informe')
      return
    }

    toast.info('Generando informe profesional...')

    try {
      const res = await fetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId: scanResult.id }),
      })

      if (!res.ok) throw new Error('Error al generar el informe')

      const htmlContent = await res.text()
      const blob = new Blob([htmlContent], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const printWindow = window.open(url, '_blank')
      if (printWindow) {
        printWindow.addEventListener('load', () => {
          toast.success('Informe abierto. Usa "Guardar como PDF" para descargar.')
        })
      } else {
        // Fallback: download as HTML
        const a = document.createElement('a')
        a.href = url
        a.download = `SpamShield-Informe-${scanResult.id.substring(0, 8)}.html`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        toast.success('Informe descargado. Ábrelo y usa "Imprimir > Guardar como PDF".')
      }
    } catch {
      toast.error('Error al generar el informe')
    }
  }

  // ── File upload handlers ──
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) validateAndSetFile(file)
  }

  const validateAndSetFile = (file: File) => {
    const allowedExtensions = ['.eml', '.pst', '.msg', '.txt']
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!allowedExtensions.includes(ext)) {
      toast.error('Formato no soportado. Usa: .eml, .pst, .msg o .txt')
      return
    }
    if (file.size > 25 * 1024 * 1024) {
      toast.error('El archivo es demasiado grande. Máximo 25MB.')
      return
    }
    setUploadedFile(file)
    toast.success(`Archivo "${file.name}" seleccionado correctamente`)
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) validateAndSetFile(file)
  }

  const removeFile = () => {
    setUploadedFile(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  // ── OAuth connect handlers (UI-only) ──
  const handleConnectProvider = (provider: string) => {
    toast.info('Funcionalidad de OAuth en desarrollo', {
      description: `La conexión con ${provider} estará disponible pronto.`,
      duration: 4000,
    })
  }

  // ── Format file size ──
  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  // ── Format date ──
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('es-ES', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  /* ============================================================
     RENDER
     ============================================================ */

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      {/* ============================================================
          SECTION 1: HEADER
          ============================================================ */}
      <header className="sticky top-0 z-50 border-b border-border/50 bg-gradient-to-r from-background via-background to-emerald-950/20 dark:from-zinc-950 dark:via-zinc-950 dark:to-emerald-950/30 backdrop-blur-xl">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16 md:h-18">
            {/* Logo & Name */}
            <div className="flex items-center gap-2.5">
              <div className="relative">
                <div className="flex items-center justify-center size-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                  <Shield className="size-5 text-emerald-500" />
                </div>
                <div className="absolute -top-0.5 -right-0.5 size-2.5 rounded-full bg-emerald-500 animate-pulse" />
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-bold tracking-tight leading-none">
                  Spam<span className="text-emerald-500">Shield</span> AI
                </span>
                <span className="text-[10px] text-muted-foreground leading-none mt-0.5 hidden sm:block">
                  Analizador Inteligente de Correos Spam
                </span>
              </div>
            </div>

            {/* Right side */}
            <div className="flex items-center gap-2">
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                      className="size-9"
                    >
                      <Sun className="size-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                      <Moon className="absolute size-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
                      <span className="sr-only">Cambiar tema</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Cambiar tema</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>

              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" className="size-9" asChild>
                      <a href="https://github.com" target="_blank" rel="noopener noreferrer">
                        <Github className="size-4" />
                        <span className="sr-only">GitHub</span>
                      </a>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>GitHub</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          </div>
        </div>
      </header>

      {/* ============================================================
          MAIN CONTENT
          ============================================================ */}
      <main className="flex-1">
        {/* ============================================================
            SECTION 2: HERO
            ============================================================ */}
        <section className="relative overflow-hidden border-b border-border/50">
          {/* Background decorative elements */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-emerald-500/5 blur-3xl" />
            <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-emerald-500/3 blur-3xl" />
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-emerald-500/2 blur-3xl" />
          </div>

          <div className="container relative mx-auto px-4 sm:px-6 lg:px-8 py-16 md:py-24">
            <motion.div
              initial="hidden"
              animate="visible"
              variants={fadeIn}
              className="text-center max-w-3xl mx-auto space-y-6"
            >
              {/* Badge */}
              <motion.div variants={scaleIn} className="flex justify-center">
                <Badge
                  variant="outline"
                  className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 px-4 py-1.5 text-sm"
                >
                  <Zap className="size-3.5 mr-1.5" />
                  Potenciado por Inteligencia Artificial
                </Badge>
              </motion.div>

              {/* Heading */}
              <div className="space-y-4">
                <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight leading-tight">
                  Detecta amenazas en tus{' '}
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-emerald-600">
                    correos electrónicos
                  </span>
                </h1>
                <p className="text-base sm:text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                  Analiza correos electrónicos sospechosos con IA avanzada. Detecta phishing,
                  estafas, contenido generado por IA y obtén informes profesionales en segundos.
                </p>
              </div>

              {/* CTA */}
              <motion.div variants={fadeIn} className="flex flex-col sm:flex-row gap-3 justify-center">
                <Button
                  size="lg"
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-8 gap-2 shadow-lg shadow-emerald-500/20"
                  onClick={() => {
                    document.getElementById('scanner-section')?.scrollIntoView({ behavior: 'smooth' })
                  }}
                >
                  <Scan className="size-4" />
                  Analizar Ahora
                  <ArrowRight className="size-4" />
                </Button>
                <Button
                  variant="outline"
                  size="lg"
                  className="px-8 gap-2"
                  onClick={() => {
                    document.getElementById('history-section')?.scrollIntoView({ behavior: 'smooth' })
                  }}
                >
                  <History className="size-4" />
                  Ver Historial
                </Button>
              </motion.div>
            </motion.div>

            {/* Feature Cards */}
            <motion.div
              initial="hidden"
              animate="visible"
              variants={staggerContainer}
              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-16"
            >
              {[
                {
                  icon: <ShieldCheck className="size-5" />,
                  title: 'Detección de Spam',
                  desc: 'Análisis profundo con IA para identificar patrones de spam conocidos y emergentes.',
                  color: 'text-emerald-400',
                  bg: 'bg-emerald-500/10',
                  border: 'border-emerald-500/20',
                },
                {
                  icon: <UserX className="size-5" />,
                  title: 'Detección de Phishing',
                  desc: 'Identifica intentos de suplantación de identidad y estafas de ingeniería social.',
                  color: 'text-red-400',
                  bg: 'bg-red-500/10',
                  border: 'border-red-500/20',
                },
                {
                  icon: <Bot className="size-5" />,
                  title: 'Contenido Generado por IA',
                  desc: 'Detecta correos escritos por inteligencia artificial con alta precisión.',
                  color: 'text-amber-400',
                  bg: 'bg-amber-500/10',
                  border: 'border-amber-500/20',
                },
                {
                  icon: <FileText className="size-5" />,
                  title: 'Informes PDF',
                  desc: 'Genera informes profesionales descargables con todos los detalles del análisis.',
                  color: 'text-emerald-400',
                  bg: 'bg-emerald-500/10',
                  border: 'border-emerald-500/20',
                },
              ].map((feature) => (
                <motion.div key={feature.title} variants={fadeIn}>
                  <Card
                    className={`group relative overflow-hidden border ${feature.border} bg-card/50 backdrop-blur-sm hover:bg-card/80 transition-all duration-300 hover:shadow-lg hover:shadow-emerald-500/5`}
                  >
                    <CardContent className="p-5 space-y-3">
                      <div
                        className={`flex items-center justify-center size-10 rounded-lg ${feature.bg} ${feature.color}`}
                      >
                        {feature.icon}
                      </div>
                      <h3 className="font-semibold text-sm">{feature.title}</h3>
                      <p className="text-xs text-muted-foreground leading-relaxed">{feature.desc}</p>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </motion.div>
          </div>
        </section>

        {/* ============================================================
            SECTION 3: SCANNER
            ============================================================ */}
        <section id="scanner-section" className="border-b border-border/50">
          <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12 md:py-16">
            <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: '-100px' }} variants={slideUp} className="space-y-6">
              <div className="text-center space-y-2">
                <h2 className="text-2xl md:text-3xl font-bold tracking-tight">
                  Analizar Correo Electrónico
                </h2>
                <p className="text-muted-foreground text-sm md:text-base">
                  Selecciona un método de análisis para comenzar
                </p>
              </div>

              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full max-w-4xl mx-auto">
                <TabsList className="w-full grid grid-cols-3 h-auto p-1">
                  <TabsTrigger value="texto" className="gap-1.5 py-2.5 text-xs sm:text-sm">
                    <FileText className="size-3.5" />
                    <span className="hidden sm:inline">Analizar Texto</span>
                    <span className="sm:hidden">Texto</span>
                  </TabsTrigger>
                  <TabsTrigger value="archivo" className="gap-1.5 py-2.5 text-xs sm:text-sm">
                    <Upload className="size-3.5" />
                    <span className="hidden sm:inline">Subir Archivo</span>
                    <span className="sm:hidden">Archivo</span>
                  </TabsTrigger>
                  <TabsTrigger value="bandeja" className="gap-1.5 py-2.5 text-xs sm:text-sm">
                    <Inbox className="size-3.5" />
                    <span className="hidden sm:inline">Conectar Bandeja</span>
                    <span className="sm:hidden">Bandeja</span>
                  </TabsTrigger>
                </TabsList>

                {/* ── Tab 1: Text Analysis ── */}
                <TabsContent value="texto" className="mt-4">
                  <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-lg">
                        <FileText className="size-5 text-emerald-400" />
                        Pegar Contenido del Correo
                      </CardTitle>
                      <CardDescription>
                        Pega el contenido completo del correo electrónico, incluyendo encabezados si es posible, para un análisis más preciso.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <Textarea
                        placeholder={`From: sender@example.com\nTo: recipient@example.com\nSubject: Urgent action required\nDate: Mon, 01 Jan 2025 10:00:00 +0000\n\nBody of the email here...`}
                        className="min-h-[250px] sm:min-h-[300px] font-mono text-sm resize-none"
                        value={emailContent}
                        onChange={(e) => setEmailContent(e.target.value)}
                      />
                      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                        <p className="text-xs text-muted-foreground">
                          {emailContent.length > 0
                            ? `${emailContent.length} caracteres`
                            : 'Soporta texto plano, encabezados MIME y contenido HTML'}
                        </p>
                        <Button
                          onClick={handleScanText}
                          disabled={isScanning || !emailContent.trim()}
                          className="bg-emerald-600 hover:bg-emerald-500 text-white gap-2 min-w-[200px] shadow-lg shadow-emerald-500/20"
                        >
                          {isScanning ? (
                            <>
                              <Loader2 className="size-4 animate-spin" />
                              Analizando...
                            </>
                          ) : (
                            <>
                              <Shield className="size-4" />
                              Analizar Correo
                            </>
                          )}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* ── Tab 2: File Upload ── */}
                <TabsContent value="archivo" className="mt-4">
                  <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-lg">
                        <Upload className="size-5 text-emerald-400" />
                        Subir Archivo de Correo
                      </CardTitle>
                      <CardDescription>
                        Arrastra y suelta o haz clic para seleccionar un archivo. Formatos soportados: .eml, .pst, .msg, .txt
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {/* Drop zone */}
                      <div
                        className={`relative border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-all duration-200 cursor-pointer ${
                          isDragOver
                            ? 'border-emerald-500 bg-emerald-500/10'
                            : uploadedFile
                              ? 'border-emerald-500/30 bg-emerald-500/5'
                              : 'border-border hover:border-emerald-500/30 hover:bg-muted/50'
                        }`}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        onClick={() => fileInputRef.current?.click()}
                      >
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept=".eml,.pst,.msg,.txt"
                          onChange={handleFileChange}
                          className="hidden"
                        />

                        {uploadedFile ? (
                          <div className="space-y-3">
                            <div className="flex items-center justify-center size-14 rounded-full bg-emerald-500/10 mx-auto">
                              <FileText className="size-7 text-emerald-400" />
                            </div>
                            <div>
                              <p className="font-medium text-sm">{uploadedFile.name}</p>
                              <p className="text-xs text-muted-foreground mt-1">
                                {formatFileSize(uploadedFile.size)}
                              </p>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation()
                                removeFile()
                              }}
                              className="text-red-400 hover:text-red-300 hover:bg-red-500/10 gap-1"
                            >
                              <Trash2 className="size-3.5" />
                              Eliminar archivo
                            </Button>
                          </div>
                        ) : (
                          <div className="space-y-3">
                            <div className="flex items-center justify-center size-14 rounded-full bg-muted/50 mx-auto">
                              <Upload className="size-7 text-muted-foreground" />
                            </div>
                            <div>
                              <p className="font-medium text-sm">
                                Arrastra tu archivo aquí o{' '}
                                <span className="text-emerald-400">haz clic para seleccionar</span>
                              </p>
                              <p className="text-xs text-muted-foreground mt-1">
                                .eml, .pst, .msg, .txt — Máximo 25MB
                              </p>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="flex justify-end">
                        <Button
                          onClick={handleScanFile}
                          disabled={isScanning || !uploadedFile}
                          className="bg-emerald-600 hover:bg-emerald-500 text-white gap-2 min-w-[200px] shadow-lg shadow-emerald-500/20"
                        >
                          {isScanning ? (
                            <>
                              <Loader2 className="size-4 animate-spin" />
                              Analizando...
                            </>
                          ) : (
                            <>
                              <Shield className="size-4" />
                              Analizar Archivo
                            </>
                          )}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* ── Tab 3: Connect Mailbox ── */}
                <TabsContent value="bandeja" className="mt-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {/* Gmail */}
                    <Card className="border-border/50 bg-card/50 backdrop-blur-sm group hover:shadow-lg hover:shadow-emerald-500/5 transition-all duration-300">
                      <CardHeader className="text-center">
                        <div className="flex justify-center mb-3">
                          <div className="flex items-center justify-center size-16 rounded-2xl bg-red-500/10 border border-red-500/20">
                            <svg className="size-8" viewBox="0 0 24 24" fill="none">
                              <path d="M22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6z" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                              <path d="M2 6l10 7 10-7" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                            </svg>
                          </div>
                        </div>
                        <CardTitle className="text-lg">Gmail</CardTitle>
                        <CardDescription>
                          Conecta tu cuenta de Gmail para analizar correos automáticamente en tiempo real.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <Button
                          variant="outline"
                          className="w-full border-red-500/30 text-red-400 hover:bg-red-500/10 hover:text-red-300 gap-2"
                          onClick={() => handleConnectProvider('Gmail')}
                        >
                          <Lock className="size-4" />
                          Conectar Gmail
                        </Button>
                      </CardContent>
                    </Card>

                    {/* Outlook */}
                    <Card className="border-border/50 bg-card/50 backdrop-blur-sm group hover:shadow-lg hover:shadow-emerald-500/5 transition-all duration-300">
                      <CardHeader className="text-center">
                        <div className="flex justify-center mb-3">
                          <div className="flex items-center justify-center size-16 rounded-2xl bg-sky-500/10 border border-sky-500/20">
                            <svg className="size-8" viewBox="0 0 24 24" fill="none">
                              <rect x="2" y="4" width="20" height="16" rx="3" stroke="#0ea5e9" strokeWidth="1.5"/>
                              <path d="M2 7l10 6 10-6" stroke="#0ea5e9" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                            </svg>
                          </div>
                        </div>
                        <CardTitle className="text-lg">Outlook</CardTitle>
                        <CardDescription>
                          Conecta tu cuenta de Outlook/Microsoft 365 para análisis continuo de seguridad.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <Button
                          variant="outline"
                          className="w-full border-sky-500/30 text-sky-400 hover:bg-sky-500/10 hover:text-sky-300 gap-2"
                          onClick={() => handleConnectProvider('Outlook')}
                        >
                          <Lock className="size-4" />
                          Conectar Outlook
                        </Button>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>
              </Tabs>
            </motion.div>
          </div>
        </section>

        {/* ============================================================
            SECTION 4: RESULTS
            ============================================================ */}
        <AnimatePresence>
          {showResults && (
            <motion.section
              id="results-section"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.5 }}
              className="border-b border-border/50 overflow-hidden"
            >
              <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12 md:py-16">
                <motion.div
                  initial="hidden"
                  animate="visible"
                  variants={staggerContainer}
                  className="space-y-6"
                >
                  <div className="text-center space-y-2">
                    <h2 className="text-2xl md:text-3xl font-bold tracking-tight">
                      Resultados del Análisis
                    </h2>
                    <p className="text-muted-foreground text-sm md:text-base">
                      Evaluación detallada de la amenaza
                    </p>
                  </div>

                  {isScanning && !scanResult ? (
                    <AnalysisLoadingSkeleton />
                  ) : scanResult ? (
                    <div className="space-y-6">
                      {/* Top row: Gauge + Summary cards */}
                      <div className="flex flex-col lg:flex-row gap-6">
                        {/* Threat Gauge */}
                        <motion.div variants={scaleIn} className="shrink-0">
                          <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                            <CardContent className="p-6">
                              <ThreatGauge score={scanResult.spamScore} />
                            </CardContent>
                          </Card>
                        </motion.div>

                        {/* Summary Cards Grid */}
                        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <motion.div variants={fadeIn}>
                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm h-full">
                              <CardContent className="p-4 space-y-2">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                                    Spam Score
                                  </span>
                                  <Mail className="size-4 text-muted-foreground" />
                                </div>
                                <div className="flex items-baseline gap-1.5">
                                  <span
                                    className={`text-2xl font-bold ${scanResult.spamScore < 30 ? 'text-emerald-400' : scanResult.spamScore < 60 ? 'text-amber-400' : 'text-red-400'}`}
                                  >
                                    {scanResult.spamScore}%
                                  </span>
                                </div>
                                <Progress
                                  value={scanResult.spamScore}
                                  className={`h-2 ${scanResult.spamScore < 30 ? '[&>[data-slot=progress-indicator]]:bg-emerald-500' : scanResult.spamScore < 60 ? '[&>[data-slot=progress-indicator]]:bg-amber-500' : '[&>[data-slot=progress-indicator]]:bg-red-500'}`}
                                />
                              </CardContent>
                            </Card>
                          </motion.div>

                          <motion.div variants={fadeIn}>
                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm h-full">
                              <CardContent className="p-4 space-y-2">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                                    Prob. IA
                                  </span>
                                  <Brain className="size-4 text-muted-foreground" />
                                </div>
                                <div className="flex items-baseline gap-1.5">
                                  <span className="text-2xl font-bold text-amber-400">
                                    {scanResult.aiConfidence}%
                                  </span>
                                </div>
                                <Progress
                                  value={scanResult.aiConfidence}
                                  className="h-2 [&>[data-slot=progress-indicator]]:bg-amber-500"
                                />
                              </CardContent>
                            </Card>
                          </motion.div>

                          <motion.div variants={fadeIn}>
                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm h-full">
                              <CardContent className="p-4 space-y-2">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                                    Tipo de Amenaza
                                  </span>
                                  <ShieldAlert className="size-4 text-muted-foreground" />
                                </div>
                                <span className="text-sm font-semibold">
                                  {getThreatTypeLabel(scanResult.threatType)}
                                </span>
                                <Badge
                                  variant="outline"
                                  className={`${
                                    scanResult.threatType === 'none'
                                      ? 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
                                      : 'border-red-500/30 text-red-400 bg-red-500/10'
                                  }`}
                                >
                                  {scanResult.isSpam ? 'Spam Detectado' : 'No es Spam'}
                                </Badge>
                              </CardContent>
                            </Card>
                          </motion.div>

                          <motion.div variants={fadeIn}>
                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm h-full">
                              <CardContent className="p-4 space-y-2">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                                    Generado por IA
                                  </span>
                                  <Bot className="size-4 text-muted-foreground" />
                                </div>
                                <span className="text-sm font-semibold">
                                  {scanResult.isAiGenerated ? 'Sí — Alta probabilidad' : 'No — Probablemente humano'}
                                </span>
                                <Badge
                                  variant="outline"
                                  className={`${
                                    scanResult.isAiGenerated
                                      ? 'border-amber-500/30 text-amber-400 bg-amber-500/10'
                                      : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
                                  }`}
                                >
                                  {scanResult.isAiGenerated ? 'IA Detectada' : 'Contenido Humano'}
                                </Badge>
                              </CardContent>
                            </Card>
                          </motion.div>
                        </div>
                      </div>

                      <Separator />

                      {/* Summary */}
                      <motion.div variants={fadeIn}>
                        <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                          <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                              <Eye className="size-5 text-emerald-400" />
                              Resumen del Análisis
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-sm text-muted-foreground leading-relaxed">
                              {scanResult.summary}
                            </p>
                          </CardContent>
                        </Card>
                      </motion.div>

                      {/* Sender Analysis */}
                      <motion.div variants={fadeIn}>
                        <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                          <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                              <ShieldCheck className="size-5 text-emerald-400" />
                              Análisis del Remitente
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-sm text-muted-foreground leading-relaxed">
                              {scanResult.senderAnalysis}
                            </p>
                          </CardContent>
                        </Card>
                      </motion.div>

                      {/* Detailed Analysis (Collapsible with ReactMarkdown) */}
                      <motion.div variants={fadeIn}>
                        <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                          <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                              <BarChart3 className="size-5 text-emerald-400" />
                              Análisis Detallado
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-4">
                            <div
                              className={`prose prose-sm dark:prose-invert max-w-none overflow-hidden transition-all duration-300 ${
                                expandedAnalysis ? 'max-h-[2000px]' : 'max-h-96'
                              }`}
                            >
                              <ReactMarkdown>{scanResult.detailedAnalysis}</ReactMarkdown>
                            </div>
                            {scanResult.detailedAnalysis.length > 500 && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setExpandedAnalysis(!expandedAnalysis)}
                                className="gap-1 text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 mx-auto flex"
                              >
                                {expandedAnalysis ? (
                                  <>
                                    Ver menos
                                    <ChevronDown className="size-4 rotate-180" />
                                  </>
                                ) : (
                                  <>
                                    Ver más
                                    <ChevronDown className="size-4" />
                                  </>
                                )}
                              </Button>
                            )}
                          </CardContent>
                        </Card>
                      </motion.div>

                      {/* Recommendations */}
                      <motion.div variants={fadeIn}>
                        <Card className="border-emerald-500/20 bg-emerald-500/5">
                          <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-lg">
                              <CheckCircle className="size-5 text-emerald-400" />
                              Recomendaciones
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="prose prose-sm dark:prose-invert max-w-none">
                              <ReactMarkdown>{scanResult.recommendations}</ReactMarkdown>
                            </div>
                          </CardContent>
                        </Card>
                      </motion.div>

                      {/* Action Buttons */}
                      <motion.div variants={fadeIn} className="flex flex-col sm:flex-row gap-3 justify-center">
                        <Button
                          onClick={handleGenerateReport}
                          className="bg-emerald-600 hover:bg-emerald-500 text-white gap-2 shadow-lg shadow-emerald-500/20"
                        >
                          <Download className="size-4" />
                          Descargar Informe PDF
                        </Button>
                        <Button
                          variant="outline"
                          onClick={() => {
                            setShowResults(false)
                            setScanResult(null)
                            setEmailContent('')
                            setExpandedAnalysis(false)
                          }}
                          className="gap-2"
                        >
                          <Scan className="size-4" />
                          Nuevo Análisis
                        </Button>
                      </motion.div>
                    </div>
                  ) : null}
                </motion.div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* ============================================================
            SECTION 5: HISTORY
            ============================================================ */}
        <section id="history-section">
          <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12 md:py-16">
            <motion.div
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, margin: '-100px' }}
              variants={slideUp}
              className="space-y-6"
            >
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div className="space-y-1">
                  <h2 className="text-2xl md:text-3xl font-bold tracking-tight flex items-center gap-2">
                    <History className="size-6 text-emerald-400" />
                    Historial de Análisis
                  </h2>
                  <p className="text-muted-foreground text-sm">
                    Registro de todos los correos analizados
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={loadHistory}
                  disabled={isLoadingHistory}
                  className="gap-2"
                >
                  <ArrowRight className="size-3.5 rotate-[270deg]" />
                  Actualizar
                </Button>
              </div>

              <Card className="border-border/50 bg-card/50 backdrop-blur-sm overflow-hidden">
                <CardContent className="p-0">
                  {isLoadingHistory ? (
                    <div className="p-6 space-y-4">
                      {Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="flex items-center gap-4">
                          <Skeleton className="h-4 w-28" />
                          <Skeleton className="h-4 w-20" />
                          <Skeleton className="h-4 flex-1" />
                          <Skeleton className="h-6 w-20" />
                        </div>
                      ))}
                    </div>
                  ) : history.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-center space-y-3">
                      <div className="flex items-center justify-center size-16 rounded-full bg-muted/50">
                        <History className="size-8 text-muted-foreground/50" />
                      </div>
                      <p className="text-sm text-muted-foreground">
                        No hay análisis registrados todavía
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Los correos analizados aparecerán aquí
                      </p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow className="border-border/50 hover:bg-muted/30">
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                              <div className="flex items-center gap-1.5">
                                <Clock className="size-3.5" />
                                Fecha
                              </div>
                            </TableHead>
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                              Fuente
                            </TableHead>
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground hidden sm:table-cell">
                              Remitente
                            </TableHead>
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground hidden md:table-cell">
                              Asunto
                            </TableHead>
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                              Veredicto
                            </TableHead>
                            <TableHead className="text-xs font-semibold uppercase tracking-wider text-muted-foreground text-right">
                              Acciones
                            </TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {history.map((entry) => {
                            const score = entry.spamScore ?? 0
                            const verdict = getVerdictInfo(score)
                            return (
                              <TableRow
                                key={entry.id}
                                className="border-border/30 hover:bg-muted/20 transition-colors"
                              >
                                <TableCell className="text-xs whitespace-nowrap">
                                  {formatDate(entry.createdAt)}
                                </TableCell>
                                <TableCell>
                                  <Badge variant="secondary" className="text-xs">
                                    {getSourceLabel(entry.source)}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-xs max-w-[150px] truncate hidden sm:table-cell">
                                  {entry.senderEmail || entry.senderName || '—'}
                                </TableCell>
                                <TableCell className="text-xs max-w-[200px] truncate hidden md:table-cell">
                                  {entry.subject || 'Sin asunto'}
                                </TableCell>
                                <TableCell>
                                  <Badge
                                    variant="outline"
                                    className={`${verdict.bgColor} ${verdict.borderColor} ${verdict.color} border text-xs`}
                                  >
                                    {verdict.label}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-right">
                                  <div className="flex items-center justify-end gap-1">
                                    <TooltipProvider>
                                      <Tooltip>
                                        <TooltipTrigger asChild>
                                          <Dialog
                                            open={showAnalysisDialog && selectedHistoryEntry?.id === entry.id}
                                            onOpenChange={(open) => {
                                              setShowAnalysisDialog(open)
                                              setSelectedHistoryEntry(open ? entry : null)
                                            }}
                                          >
                                            <DialogTrigger asChild>
                                              <Button variant="ghost" size="icon" className="size-8">
                                                <Eye className="size-3.5" />
                                                <span className="sr-only">Ver detalles</span>
                                              </Button>
                                            </DialogTrigger>
                                            <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                                              <DialogHeader>
                                                <DialogTitle className="flex items-center gap-2">
                                                  <Shield className="size-5 text-emerald-400" />
                                                  Detalles del Análisis
                                                </DialogTitle>
                                                <DialogDescription>
                                                  {formatDate(entry.createdAt)} — {getSourceLabel(entry.source)}
                                                </DialogDescription>
                                              </DialogHeader>
                                              <div className="space-y-4 mt-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                  <div>
                                                    <span className="text-xs text-muted-foreground">Remitente</span>
                                                    <p className="text-sm font-medium">{entry.senderEmail || entry.senderName || 'Desconocido'}</p>
                                                  </div>
                                                  <div>
                                                    <span className="text-xs text-muted-foreground">Asunto</span>
                                                    <p className="text-sm font-medium">{entry.subject || 'Sin asunto'}</p>
                                                  </div>
                                                  <div>
                                                    <span className="text-xs text-muted-foreground">Puntuación Spam</span>
                                                    <p className="text-sm font-medium">{entry.spamScore !== null ? `${entry.spamScore}%` : 'N/A'}</p>
                                                  </div>
                                                  <div>
                                                    <span className="text-xs text-muted-foreground">Tipo de Amenaza</span>
                                                    <p className="text-sm font-medium">{getThreatTypeLabel(entry.threatType || 'unknown')}</p>
                                                  </div>
                                                </div>
                                                <Separator />
                                                <Badge
                                                  variant="outline"
                                                  className={`${verdict.bgColor} ${verdict.borderColor} ${verdict.color} border px-4 py-1.5 text-sm font-semibold self-start`}
                                                >
                                                  {verdict.icon}
                                                  <span className="ml-1.5">{verdict.label}</span>
                                                </Badge>
                                              </div>
                                            </DialogContent>
                                          </Dialog>
                                        </TooltipTrigger>
                                        <TooltipContent>
                                          <p>Ver detalles</p>
                                        </TooltipContent>
                                      </Tooltip>
                                    </TooltipProvider>
                                  </div>
                                </TableCell>
                              </TableRow>
                            )
                          })}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </section>
      </main>

      {/* ============================================================
          SECTION 6: FOOTER
          ============================================================ */}
      <footer className="mt-auto border-t border-border/50 bg-muted/30 backdrop-blur-sm">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            {/* Left: Logo */}
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-emerald-500" />
              <span className="text-sm font-semibold">
                Spam<span className="text-emerald-500">Shield</span> AI
              </span>
            </div>

            {/* Center: Links */}
            <nav className="flex items-center gap-4 sm:gap-6">
              <a
                href="#"
                className="text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                Privacidad
              </a>
              <a
                href="#"
                className="text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                Términos
              </a>
              <a
                href="#"
                className="text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                Contacto
              </a>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-muted-foreground hover:text-foreground transition-colors"
                    >
                      <Github className="size-4" />
                    </a>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>GitHub</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </nav>

            {/* Right: Powered by */}
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Globe className="size-3" />
              <span>Powered by</span>
              <span className="font-semibold text-foreground">Z.ai</span>
            </div>
          </div>

          <Separator className="my-4" />

          <div className="text-center">
            <p className="text-xs text-muted-foreground">
              © {new Date().getFullYear()} SpamShield AI. Todos los derechos reservados. Herramienta de ciberseguridad profesional.
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}
