"use client"

import { useEffect, useRef } from "react"

interface CodeBlockProps {
  code: string
  language: string
  caption?: string
  isVulnerable?: boolean
}

export default function CodeBlock({ code, language, caption, isVulnerable }: CodeBlockProps) {
  const codeRef = useRef<HTMLElement>(null)

  useEffect(() => {
    // Importar Prism solo en el cliente
    const loadPrism = async () => {
      // Importación dinámica de Prism
      const Prism = (await import("prismjs")).default

      // Importar tema y lenguajes
      await import("prismjs/themes/prism-tomorrow.css")

      // Importar lenguajes específicos
      await import("prismjs/components/prism-javascript")
      await import("prismjs/components/prism-typescript")
      await import("prismjs/components/prism-bash")
      await import("prismjs/components/prism-json")
      await import("prismjs/components/prism-kotlin")
      await import("prismjs/components/prism-swift")
      await import("prismjs/components/prism-java")
      await import("prismjs/components/prism-python")
      await import("prismjs/components/prism-solidity")
      await import("prismjs/components/prism-docker")
      await import("prismjs/components/prism-hcl")
      await import("prismjs/components/prism-yaml")

      // Resaltar el código actual
      if (codeRef.current) {
        Prism.highlightElement(codeRef.current)
      }
    }

    loadPrism()
  }, [code])

  const captionColor = isVulnerable ? "text-red-400" : "text-green-400"

  return (
    <div className="mb-4">
      {caption && <p className={`${captionColor} mb-2`}>{caption}</p>}
      <pre className="rounded-lg overflow-x-auto bg-[#2d2d2d] p-4">
        <code ref={codeRef} className={`language-${language}`}>
          {code}
        </code>
      </pre>
    </div>
  )
}
