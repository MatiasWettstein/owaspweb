"use client"

import CodeBlock from "@/components/basic/code-block"
import Footer from "@/components/basic/footer"
import Card from "@/components/basic/card"
import Accordion from "@/components/basic/accordion"
import CloudHeader from "@/components/cloud/cloud-header"
import CloudIntroduction from "@/components/cloud/cloud-introduction"
import CloudStatistics from "@/components/cloud/cloud-statistics"
import CloudResources from "@/components/cloud/cloud-resources"
import cloudData from "@/data/cloud"

export default function CloudTop10Page() {

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
      <CloudHeader />
      <CloudIntroduction />
      <main className="py-12 px-4 md:px-8 lg:px-16">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold mb-8 text-center">Los 10 Riesgos Principales</h2>
          {Object.values(cloudData).map((risk, index) => (
            <Card {...{ ...risk, position: index + 1 }} key={index} headerColor="bg-cyan-700" positionColor="text-cyan-700" exampleTitle="Ejemplo de implementación">
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
              </>
            </Card>
          ))}
        </div>
      </main>
      <CloudStatistics />
      <CloudResources />
      <Footer />
    </div>
  )
}
