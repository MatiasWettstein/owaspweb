"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield, Menu, X } from "lucide-react"
import { useState } from "react"
import { motion } from "framer-motion"

export default function HeaderNav() {
  const pathname = usePathname()
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const navItems = [
    { name: "INICIO", path: "/" },
    { name: "API", path: "/api" },
    { name: "WEB", path: "/web" },
    { name: "MOVIL", path: "/movil" },
    { name: "CLOUD", path: "/cloud" },
    { name: "CRIPTOGRAFIA", path: "/criptografia" },
    { name: "RECURSOS", path: "/recursos" },
  ]

  return (
    <motion.div
      initial={{ y: -200 }}
      animate={{ y: 0 }}
      transition={{ duration: 1 }}
      className="bg-slate-900/10 border-b border-slate-800 z-10 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link href="/" className="flex items-center text-white">
              <Shield className="h-8 w-8 text-red-500 mr-2" />
              <span className="font-bold text-xl">Desarrollo Seguro</span>
            </Link>
          </div>

          {/* Desktop navigation */}
          <div className="hidden md:flex space-x-4">
            {navItems.map((item) => (
              <Link
                key={item.name}
                href={item.path}
                className={`px-3 py-2 rounded-md text-sm font-medium ${pathname === item.path ? "bg-cyan-950 text-white" : "text-gray-300 hover:bg-slate-800 hover:text-white"
                  }`}
              >
                {item.name}
              </Link>
            ))}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="text-gray-300 hover:text-white focus:outline-none"
            >
              {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>
      </div>

      {isMenuOpen && (
        <div className="md:hidden bg-slate-800">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            {navItems.map((item) => (
              <Link
                key={item.name}
                href={item.path}
                className={`block px-3 py-2 rounded-md text-base font-medium ${pathname === item.path ? "bg-cyan-950 text-white" : "text-gray-300 hover:bg-slate-700 hover:text-white"
                  }`}
                onClick={() => setIsMenuOpen(false)}
              >
                {item.name}
              </Link>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}