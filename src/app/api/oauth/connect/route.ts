'use server'

import { NextRequest, NextResponse } from 'next/server'

// In-memory store for OAuth connections (demo mode)
const connections: Record<string, { provider: string; email: string; name: string; connectedAt: string; token: string }> = {}

// Simulated OAuth tokens
function generateToken(): string {
  return `demo_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
}

// Demo account data per provider
const DEMO_ACCOUNTS = {
  google: {
    email: 'usuario@gmail.com',
    name: 'Usuario Demo',
    avatar: null,
  },
  microsoft: {
    email: 'usuario@outlook.com',
    name: 'Usuario Demo',
    avatar: null,
  },
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { provider, code } = body

    if (!provider || !['google', 'microsoft'].includes(provider)) {
      return NextResponse.json(
        { error: 'Proveedor no soportado. Usa google o microsoft.' },
        { status: 400 }
      )
    }

    // Simulate OAuth handshake delay
    await new Promise((resolve) => setTimeout(resolve, 1500 + Math.random() * 1000))

    const account = DEMO_ACCOUNTS[provider as keyof typeof DEMO_ACCOUNTS]
    const token = generateToken()

    // Store connection
    connections[provider] = {
      provider,
      email: account.email,
      name: account.name,
      connectedAt: new Date().toISOString(),
      token,
    }

    return NextResponse.json({
      success: true,
      provider,
      email: account.email,
      name: account.name,
      connectedAt: connections[provider].connectedAt,
      message: provider === 'google'
        ? 'Cuenta de Google conectada exitosamente'
        : 'Cuenta de Microsoft conectada exitosamente',
    })
  } catch (error) {
    console.error('OAuth connect error:', error)
    return NextResponse.json(
      { error: 'Error al conectar con el proveedor. Intenta de nuevo.' },
      { status: 500 }
    )
  }
}

export async function GET() {
  // Return current connection status
  const googleConnected = !!connections.google
  const microsoftConnected = !!connections.microsoft

  return NextResponse.json({
    google: googleConnected
      ? { connected: true, email: connections.google.email, name: connections.google.name, connectedAt: connections.google.connectedAt }
      : { connected: false },
    microsoft: microsoftConnected
      ? { connected: true, email: connections.microsoft.email, name: connections.microsoft.name, connectedAt: connections.microsoft.connectedAt }
      : { connected: false },
  })
}