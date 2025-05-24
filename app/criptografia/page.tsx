"use client"

import { useState } from "react"
import HeaderNav from "@/components/basic/header-nav"
import {
    Key,
    Lock,
    Shield,
    Code,
    BookOpen,
    ArrowRight,
    RefreshCw,
    Server,
    AlertTriangle,
} from "lucide-react"
import { DynamicIcon, IconName } from 'lucide-react/dynamic';
import CodeBlock from "@/components/basic/code-block"
import criptografiaData, { CodeExample } from "@/data/criptografia"
import Footer from "@/components/basic/footer";
import Accordion from "@/components/basic/accordion";
import CriptografiaHeader from "@/components/criptografia/criptografia-header";
import CriptografiaIntroduction from "@/components/criptografia/criptografia-introduction";
import CriptografiaStatistics from "@/components/criptografia/criptografia-statistics";
import CriptografiaResources from "@/components/criptografia/criptografia-resources";
import CriptografiaBestPractices from "@/components/criptografia/criptografia-best-practices";

export default function CriptografiaPage() {

    const renderCodeExample = (example: CodeExample, index: number) => {
        const codeId = `${example.language}-${index}`
        return (
            <div key={codeId} className="bg-slate-900 p-4 rounded-lg relative">
                <Accordion title='Ejemplo'>
                    <CodeBlock
                        language={example.language}
                        code={example.code}
                        caption={example.caption}
                        isVulnerable={example.isVulnerable}
                    />
                </Accordion>
            </div>
        )
    }

    const renderCharacteristics = (characteristics: any) => {
        return (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                    <h4 className="font-bold text-indigo-400 mb-2">{characteristics.left.title}:</h4>
                    <ul className="list-disc pl-5 space-y-1">
                        {characteristics.left.items.map((item: string, index: number) => (
                            <li key={index} dangerouslySetInnerHTML={{ __html: item }} />
                        ))}
                    </ul>
                </div>
                <div>
                    <h4 className="font-bold text-indigo-400 mb-2">{characteristics.right.title}:</h4>
                    <ul className="list-disc pl-5 space-y-1">
                        {characteristics.right.items.map((item: string, index: number) => (
                            <li key={index} dangerouslySetInnerHTML={{ __html: item }} />
                        ))}
                    </ul>
                </div>
            </div>
        )
    }

    const renderSecurityPoints = (points: string[]) => {
        return (
            <div className="bg-slate-700 p-4 rounded-lg">
                <h4 className="font-bold text-indigo-300 mb-2">Puntos clave de seguridad:</h4>
                <ul className="list-disc pl-5 space-y-1 text-slate-300">
                    {points.map((point, index) => (
                        <li key={index} dangerouslySetInnerHTML={{ __html: point }} />
                    ))}
                </ul>
            </div>
        )
    }

    const renderSubsection = (subsectionKey: string, subsection: any, sectionKey: string) => {
        const id = `${sectionKey}-${subsectionKey}`
        return (
            <div key={id} className="bg-slate-800 rounded-lg overflow-hidden shadow-lg border border-slate-700 mb-8">
                <div className="bg-indigo-700 p-4">
                    <h3 className="text-2xl font-bold">{subsection.title}</h3>
                </div>
                <div className="p-6">
                    <p className="mb-4">{subsection.description}</p>

                    {subsection.characteristics && renderCharacteristics(subsection.characteristics)}

                    {subsection.examples &&
                        subsection.examples.map((example: CodeExample, index: number) => (
                            <div key={index} className="mb-6">
                                <h4 className="font-bold text-blue-400 flex items-center mb-2">
                                    <Code className="mr-2" size={18} /> Ejemplo: {example.caption || `Código en ${example.language}`}
                                </h4>
                                {renderCodeExample(example, index)}
                            </div>
                        ))}

                    {subsection.securityPoints && renderSecurityPoints(subsection.securityPoints)}
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
            <CriptografiaHeader />
            <CriptografiaIntroduction />

            <main className="py-12 px-4 md:px-8 lg:px-16">
                <div className="max-w-5xl mx-auto">
                    {Object.entries(criptografiaData).map(([sectionKey, section]) => (
                        <section key={sectionKey} className="mb-16">
                            <h2 className="text-3xl font-bold mb-8 flex items-center">
                                <DynamicIcon name={section.iconName as IconName} className="mr-3" /> {section.title}
                            </h2>

                            {Object.entries(section.subsections).map(([subsectionKey, subsection]) =>
                                renderSubsection(subsectionKey, subsection, sectionKey),
                            )}
                        </section>
                    ))}
                    <CriptografiaBestPractices />
                </div>
            </main>
            <CriptografiaStatistics />
            <CriptografiaResources />
            <Footer />
        </div>
    )
}
