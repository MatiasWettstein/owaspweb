"use client"

import Link from "next/link"
import {
  Shield,
  ArrowRight,
  Key,
  Cloud,
  PenToolIcon,
  Smartphone,
  Globe,
  Laptop,
  Server,
} from "lucide-react"
import Footer from "@/components/basic/footer"
import { motion } from "framer-motion"
import ParticleBackground from "@/components/basic/background-effect"
import { useEffect, useState } from "react"

export default function Home() {

  const securityTopics = [
    {
      title: "Top 10 para APIs",
      description: "Descubre las 10 vulnerabilidades más críticas que afectan a las APIs modernas y cómo mitigarlas.",
      icon: <Server className="h-8 w-8 text-lime-500 mb-4" />,
      href: "/api",
      color: "border-lime-500 hover:bg-lime-500/10",
      comingSoon: false
    },
    {
      title: "Top 10 para Aplicaciones Web",
      description:
        "Explora las 10 vulnerabilidades más peligrosas en aplicaciones web y aprende estrategias efectivas de protección.",
      icon: <Laptop className="h-8 w-8 text-red-500 mb-4" />,
      href: "/web",
      color: "border-red-500 hover:bg-red-500/10",
      comingSoon: false
    },
    {
      title: "Seguridad Móvil",
      description:
        "Descubre 10 Vulnerabilidades que afectan a la mayoría de aplicaciones y aprende estrategias para el desarrollo seguro.",
      icon: <Smartphone className="h-8 w-8 text-purple-500 mb-4" />,
      href: "/movil",
      color: "border-purple-500 hover:bg-purple-500/10",
      comingSoon: false
    },
    {
      title: "Seguridad en la Nube",
      description: "Explora las 10 vulnerabilidades más comunes en arquitecturas en la nube y aprende buenas prácticas para evitarlas.",
      icon: <Cloud className="h-8 w-8 text-cyan-500 mb-4" />,
      href: "/cloud",
      color: "border-cyan-500 hover:bg-cyan-500/10",
      comingSoon: false,
    },
    {
      title: "Criptografía Aplicada",
      description: "Descubre como funciona la criptografia desde lo más básico hasta implementacines prácticas de algoritmos criptográficos.",
      icon: <Key className="h-8 w-8 text-indigo-500 mb-4" />,
      href: "/criptografia",
      color: "border-indigo-500 hover:bg-indigo-500/10",
      comingSoon: false,
    },
    {
      title: "Herramientas y recursos ",
      description: "Recopilación de herramientas y recursos útiles para la seguridad en el desarrollo.",
      icon: <PenToolIcon className="h-8 w-8 text-amber-500 mb-4" />,
      href: "/recursos",
      color: "border-amber-500 hover:bg-amber-500/10",
      comingSoon: false,
    },
  ]

  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({ x: e.clientX, y: e.clientY })
    }

    window.addEventListener("mousemove", handleMouseMove)
    return () => window.removeEventListener("mousemove", handleMouseMove)
  }, [])

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
      <ParticleBackground mousePosition={mousePosition} />
      <main className="py-16 px-4 md:px-8 lg:px-16 z-10 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <motion.div
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 1 }}
              className="inline-block p-3 bg-red-600 rounded-xl mb-6">
              <Shield size={52} />
            </motion.div>
            <motion.h1
              initial={{ opacity: 0, x: -100 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 1 }}
              className="text-4xl md:text-6xl font-bold mb-6">Seguridad en Desarrollo</motion.h1>
            <motion.p
              initial={{ opacity: 0, x: 100 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 1 }}
              className="text-xl text-slate-300 max-w-3xl mx-auto">
              Recursos técnicos y guías avanzadas sobre seguridad para desarrolladores y profesionales IT
            </motion.p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {securityTopics.map((topic, index) => (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 1, delay: 0.2 * index }}
                key={index}
                className={`bg-slate-800/10 border ${topic.color} rounded-lg p-6 transition-all hover:shadow-xl flex flex-col h-full relative cursor-pointer`}
              >
                {topic.comingSoon && (
                  <div className="absolute top-4 right-4 bg-slate-700 text-xs font-semibold px-2 py-1 rounded-full">
                    Próximamente
                  </div>
                )}
                <div className="flex flex-col items-center text-center mb-4">
                  {topic.icon}
                  <h2 className="text-xl font-bold mb-2 select-none">{topic.title}</h2>
                </div>
                <p className="text-slate-300 flex-grow mb-4 text-center select-none">{topic.description}</p>
                <Link
                  href={topic.href}
                  className={`flex items-center justify-center mt-auto ${topic.comingSoon ? "opacity-50 cursor-not-allowed" : "hover:underline"}`}
                  onClick={(e) => topic.comingSoon && e.preventDefault()}
                >
                  <span className="select-none">Ver más</span>
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </motion.div>
            ))}
          </div>

          <div className="mt-16 bg-slate-800 border border-slate-700 rounded-lg p-8">
            <h2 className="text-2xl font-bold mb-4 text-center">
              ¿Por qué es importante la seguridad en el desarrollo?
            </h2>
            <p className="text-slate-300 mb-6">
              En el entorno tecnológico actual, implementar seguridad desde las fases iniciales del desarrollo es
              crucial. Los fallos de seguridad no solo pueden comprometer datos sensibles, sino también afectar la
              integridad de sistemas completos, generar pérdidas económicas significativas y dañar la reputación de las
              organizaciones.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-slate-700 p-4 rounded-lg">
                <h3 className="font-bold text-lg mb-2 flex items-center">
                  <Shield className="mr-2 text-red-400" size={20} /> Desarrollo seguro
                </h3>
                <p className="text-sm text-slate-300">
                  Integrar prácticas de seguridad desde el diseño reduce significativamente los costos de corrección y
                  mitigación posteriores.
                </p>
              </div>
              <div className="bg-slate-700 p-4 rounded-lg">
                <h3 className="font-bold text-lg mb-2 flex items-center">
                  <Key className="mr-2 text-indigo-400" size={20} /> Protección de datos
                </h3>
                <p className="text-sm text-slate-300">
                  Implementar controles adecuados para proteger información sensible y cumplir con regulaciones como
                  GDPR o HIPAA.
                </p>
              </div>
              <div className="bg-slate-700 p-4 rounded-lg">
                <h3 className="font-bold text-lg mb-2 flex items-center">
                  <Globe className="mr-2 text-green-400" size={20} /> Confiabilidad
                </h3>
                <p className="text-sm text-slate-300">
                  Desarrollar sistemas robustos que mantengan su integridad frente a intentos de explotación y ataques.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  )
}
