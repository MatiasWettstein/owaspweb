import type React from "react"
import "./globals.css"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import ScrollToTop from "@/components/basic/scroll-to-top"
import HeaderNav from "@/components/basic/header-nav"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "OWASP Top 10 para APIs y Web",
  description: "Guía completa sobre las vulnerabilidades más críticas en APIs, Aplicaciones Web y cómo mitigarlas",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="es">
      <head>
        <style>{`
          pre {
            background-color: #2d2d2d;
            border-radius: 0.375rem;
            padding: 1rem;
            overflow-x: auto;
          }
          code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.875rem;
            line-height: 1.5;
            color: #e6e6e6;
          }
        `}</style>
      </head>
      <body className={`${inter.className} bg-gradient-to-br from-slate-900 to-slate-800`} id="body">
        <HeaderNav />
        {children}
        <ScrollToTop />
      </body>
    </html>
  )
}
