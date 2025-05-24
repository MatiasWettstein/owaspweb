"use client"

import Link from "next/link"
import { Home, ShieldAlert } from "lucide-react"

export default function NotFound() {
    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white flex items-center justify-center">
            <div className="text-center px-4">
                <div className="inline-block p-3 text-red-600 rounded-lg mb-6">
                    <ShieldAlert size={180} />
                </div>
                <h1 className="text-4xl md:text-6xl font-bold mb-4">404</h1>
                <h2 className="text-2xl md:text-3xl font-semibold mb-6">Página no encontrada</h2>
                <p className="text-slate-300 max-w-md mx-auto mb-8">
                    Lo sentimos, la página que estás buscando no existe o ha sido movida.
                </p>
                <Link
                    href="/"
                    className="inline-flex items-center px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                >
                    <Home className="mr-2" size={20} />
                    Volver al inicio
                </Link>
            </div>
        </div>
    )
}