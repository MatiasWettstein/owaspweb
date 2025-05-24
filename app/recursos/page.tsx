"use client"

import Footer from "@/components/basic/footer"
import RecursosHeader from "@/components/recursos/recursos-header"
import { Book, Video, PenToolIcon as Tool, LinkIcon, ExternalLink, Code } from "lucide-react"

export default function RecursosPage() {

    const recursos = [
        {
            category: "Documentación Técnica",
            icon: <Book className="h-8 w-8 text-blue-500" />,
            items: [
                {
                    title: "OWASP Cheat Sheet Series",
                    description: "Guías técnicas sobre implementación de controles de seguridad en aplicaciones",
                    link: "https://cheatsheetseries.owasp.org/",
                },
                {
                    title: "OWASP ASVS",
                    description: "Application Security Verification Standard - Requisitos de seguridad y verificación",
                    link: "https://owasp.org/www-project-application-security-verification-standard/",
                },
                {
                    title: "OWASP Security Headers",
                    description: "Guía para implementar cabeceras HTTP de seguridad",
                    link: "https://owasp.org/www-project-secure-headers/",
                },
                {
                    title: "Mozilla Web Security Guidelines",
                    description: "Guías de seguridad web para desarrolladores",
                    link: "https://infosec.mozilla.org/guidelines/web_security",
                },
            ],
        },
        {
            category: "Herramientas para Desarrolladores",
            icon: <Tool className="h-8 w-8 text-green-500" />,
            items: [
                {
                    title: "OWASP ZAP",
                    description: "Proxy de interceptación para encontrar vulnerabilidades en aplicaciones web",
                    link: "https://www.zaproxy.org/",
                },
                {
                    title: "Burp Suite",
                    description: "Plataforma integrada para pruebas de seguridad en aplicaciones web",
                    link: "https://portswigger.net/burp",
                },
                {
                    title: "SonarQube",
                    description: "Plataforma de análisis estático de código para detectar vulnerabilidades",
                    link: "https://www.sonarqube.org/",
                },
                {
                    title: "OWASP Dependency-Check",
                    description: "Herramienta para identificar dependencias con vulnerabilidades conocidas",
                    link: "https://owasp.org/www-project-dependency-check/",
                },
            ],
        },
        {
            category: "Formación Avanzada",
            icon: <Video className="h-8 w-8 text-red-500" />,
            items: [
                {
                    title: "Hack The Box",
                    description: "Plataforma para practicar habilidades de hacking ético en entornos realistas",
                    link: "https://www.hackthebox.eu/",
                },
                {
                    title: "PortSwigger Web Security Academy",
                    description: "Laboratorios interactivos sobre vulnerabilidades web y su explotación",
                    link: "https://portswigger.net/web-security",
                },
                {
                    title: "SANS Courses",
                    description: "Cursos especializados en ciberseguridad y desarrollo seguro",
                    link: "https://www.sans.org/cyber-security-courses/",
                },
                {
                    title: "PentesterLab",
                    description: "Ejercicios prácticos para aprender sobre vulnerabilidades web",
                    link: "https://pentesterlab.com/",
                },
            ],
        },
        {
            category: "Frameworks y Bibliotecas Seguras",
            icon: <Code className="h-8 w-8 text-purple-500" />,
            items: [
                {
                    title: "OWASP ModSecurity Core Rule Set",
                    description: "Reglas para WAF que protegen contra vulnerabilidades comunes",
                    link: "https://coreruleset.org/",
                },
            ],
        },
        {
            category: "Comunidades Técnicas",
            icon: <LinkIcon className="h-8 w-8 text-yellow-500" />,
            items: [
                {
                    title: "Stack Exchange Information Security",
                    description: "Foro de preguntas y respuestas sobre seguridad informática",
                    link: "https://security.stackexchange.com/",
                },
                {
                    title: "OWASP Slack",
                    description: "Canal de Slack de la comunidad OWASP",
                    link: "https://owasp.org/slack/invite",
                },
                {
                    title: "Reddit r/netsec",
                    description: "Comunidad de Reddit dedicada a la seguridad en redes e internet",
                    link: "https://www.reddit.com/r/netsec/",
                },
                {
                    title: "HackerOne Hacktivity",
                    description: "Informes públicos de vulnerabilidades en programas de bug bounty",
                    link: "https://hackerone.com/hacktivity",
                },
            ],
        },
    ]

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">

            {/* Header */}
            <RecursosHeader />

            {/* Main Content */}
            <main className="py-12 px-4 md:px-8 lg:px-16">
                <div className="max-w-6xl mx-auto">
                    {recursos.map((categoria, index) => (
                        <div key={index} className="mb-16">
                            <div className="flex items-center mb-6">
                                <div className="bg-slate-800 p-3 rounded-lg mr-4">{categoria.icon}</div>
                                <h2 className="text-2xl font-bold">{categoria.category}</h2>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {categoria.items.map((item, itemIndex) => (
                                    <div
                                        key={itemIndex}
                                        className="bg-slate-800 border border-slate-700 rounded-lg p-5 hover:border-slate-600 transition-all"
                                    >
                                        <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                                        <p className="text-slate-300 mb-4">{item.description}</p>
                                        <a
                                            href={item.link}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="flex items-center text-blue-400 hover:text-blue-300 transition-colors"
                                        >
                                            <span>Visitar recurso</span>
                                            <ExternalLink className="ml-2 h-4 w-4" />
                                        </a>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </main>

            <Footer />
        </div>
    )
}
