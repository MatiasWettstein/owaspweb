"use client"

import HeaderNav from "@/components/basic/header-nav"
import CodeBlock from "@/components/basic/code-block"
import Footer from "@/components/basic/footer"
import Card from "@/components/basic/card"
import Accordion from "@/components/basic/accordion"
import ApiHeader from "@/components/api/api-header"
import ApiIntroduction from "@/components/api/api-introduction"
import ApiStatistics from "@/components/api/api-statistics"
import ApiResources from "@/components/api/api-resources"
import apiData from "@/data/api"

export default function ApiTop10Page() {

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
      <ApiHeader />
      <ApiIntroduction />
      <main className="py-12 px-4 md:px-8 lg:px-16">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold mb-8 text-center">Los 10 Riesgos Principales</h2>
          {Object.values(apiData).map((risk, index) => (
            <Card {...{ ...risk, position: index + 1 }} key={index} headerColor="bg-lime-700" positionColor="text-lime-700">
              <>
                <Accordion title="Ejemplo 1">
                  <CodeBlock
                    language={risk.example1.language}
                    code={risk.example1.vulnerable}
                    caption="// Código vulnerable"
                    isVulnerable={true}
                  />
                  <CodeBlock
                    language={risk.example1.language}
                    code={risk.example1.secure}
                    caption="// Código seguro"
                    isVulnerable={false}
                  />
                </Accordion>
                <Accordion title="Ejemplo 2">
                  <CodeBlock
                    language={risk.example2.language}
                    code={risk.example2.vulnerable}
                    caption="// Código vulnerable"
                    isVulnerable={true}
                  />
                  <CodeBlock
                    language={risk.example2.language}
                    code={risk.example2.secure}
                    caption="// Código seguro"
                    isVulnerable={false}
                  />
                </Accordion>
                <Accordion title="Ejemplo 3">
                  <CodeBlock
                    language={risk.example3.language}
                    code={risk.example3.vulnerable}
                    caption="// Código vulnerable"
                    isVulnerable={true}
                  />
                  <CodeBlock
                    language={risk.example3.language}
                    code={risk.example3.secure}
                    caption="// Código seguro"
                    isVulnerable={false}
                  />
                </Accordion>
              </>
            </Card>
          ))}
        </div>
      </main>
      <ApiStatistics />
      <ApiResources />
      <Footer />
    </div>
  )
}
