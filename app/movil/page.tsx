"use client"

import { useEffect, useState } from "react"
import HeaderNav from "@/components/basic/header-nav"
import {
    Smartphone,
    AlertTriangle,
    Shield,
    Code,
    BookOpen,
    Lock,
    HardDrive,
    Network,
    ChevronDown,
    ChevronUp,
    User,
    FileText,
    Terminal,
    Eye,
    Fingerprint,
} from "lucide-react"
import CodeBlock from "@/components/basic/code-block"
import MovilHeader from "@/components/movil/movil-header"
import MovilIntroduction from "@/components/movil/movil-introduction"
import Card from "@/components/basic/card"
import Accordion from "@/components/basic/accordion"
import PlatformTabs from "@/components/movil/platform-tabs"
import MovilStatistics from "@/components/movil/movil-statistics"
import Footer from "@/components/basic/footer"
import movilData from "@/data/movil"
import MovilResources from "@/components/movil/movil-resources"

export default function SeguridadMovilPage() {
    const [activePlatform, setActivePlatform] = useState<Record<string, string>>({})

    const setPlatform = (accordionId: string, platform: string) => {
        console.log(accordionId, platform)
        setActivePlatform((prev) => ({
            ...prev,
            [accordionId]: platform,
        }))
    }

    const getPlatform = (accordionId: string) => {
        return activePlatform[accordionId] || "android"
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
            <MovilHeader />
            <MovilIntroduction />
            <main className="py-12 px-4 md:px-8 lg:px-16">
                <div className="max-w-5xl mx-auto">
                    <h2 className="text-3xl font-bold mb-8 text-center">Los 10 Riesgos Principales</h2>
                    {Object.values(movilData).map((risk, index) => (
                        <Card {...{ ...risk, position: index + 1 }} key={index} exampleTitle="Ejemplos de implementación" headerColor="bg-purple-700" positionColor="text-purple-700">
                            <>
                                <Accordion title="Ejemplo 1">
                                    <div className="mt-2">
                                        <PlatformTabs getPlatform={getPlatform} setPlatform={setPlatform} name={`example-1-${index}`} />
                                        {getPlatform(`example-1-${index}`) === "android" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (Android)"
                                                    language="kotlin"
                                                    code={risk?.example1?.kotlin.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (Android)"
                                                    language="kotlin"
                                                    code={risk?.example1?.kotlin.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-1-${index}`) === "ios" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (iOS)"
                                                    language="swift"
                                                    code={risk?.example1?.swift.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (iOS)"
                                                    language="swift"
                                                    code={risk?.example1?.swift.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-1-${index}`) === "reactnative" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (React Native)"
                                                    language="javascript"
                                                    code={risk?.example1?.reactnative.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (React Native)"
                                                    language="javascript"
                                                    code={risk?.example1?.reactnative.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                    </div>
                                </Accordion>
                                <Accordion title="Ejemplo 2">
                                    <div className="mt-2">
                                        <PlatformTabs getPlatform={getPlatform} setPlatform={setPlatform} name={`example-2-${index}`} />
                                        {getPlatform(`example-2-${index}`) === "android" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (Android)"
                                                    language="kotlin"
                                                    code={risk?.example2?.kotlin.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (Android)"
                                                    language="kotlin"
                                                    code={risk?.example2?.kotlin.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-2-${index}`) === "ios" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (iOS)"
                                                    language="swift"
                                                    code={risk?.example2?.swift.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (iOS)"
                                                    language="swift"
                                                    code={risk?.example2?.swift.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-2-${index}`) === "reactnative" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (React Native)"
                                                    language="javascript"
                                                    code={risk?.example2?.reactnative.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (React Native)"
                                                    language="javascript"
                                                    code={risk?.example2?.reactnative.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                    </div>
                                </Accordion>
                                <Accordion title="Ejemplo 3">
                                    <div className="mt-2">
                                        <PlatformTabs getPlatform={getPlatform} setPlatform={setPlatform} name={`example-3-${index}`} />
                                        {getPlatform(`example-3-${index}`) === "android" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (Android)"
                                                    language="kotlin"
                                                    code={risk?.example3?.kotlin.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (Android)"
                                                    language="kotlin"
                                                    code={risk?.example3?.kotlin.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-3-${index}`) === "ios" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (iOS)"
                                                    language="swift"
                                                    code={risk?.example3?.swift.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (iOS)"
                                                    language="swift"
                                                    code={risk?.example3?.swift.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                        {getPlatform(`example-3-${index}`) === "reactnative" && (
                                            <>
                                                <CodeBlock
                                                    caption="// Código vulnerable (React Native)"
                                                    language="javascript"
                                                    code={risk?.example3?.reactnative.vulnerable}
                                                    isVulnerable={true}
                                                />
                                                <CodeBlock
                                                    caption="// Código seguro (React Native)"
                                                    language="javascript"
                                                    code={risk?.example3?.reactnative.secure}
                                                    isVulnerable={false}
                                                />
                                            </>
                                        )}
                                    </div>
                                </Accordion>
                            </>
                        </Card>
                    ))}
                </div>
            </main>
            <MovilStatistics />
            <MovilResources />
            <Footer />
        </div>
    )
}
