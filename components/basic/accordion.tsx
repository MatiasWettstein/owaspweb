"use client"

import { ChevronDown } from "lucide-react"
import { useState } from "react"

interface AccordionProps {
    title: string
    children: React.ReactNode
    defaultOpen?: boolean
}

export default function Accordion({ title, children, defaultOpen = false }: AccordionProps) {
    const [isOpen, setIsOpen] = useState(defaultOpen)

    return (
        <div className="mb-4">
            <button
                className={`
                    w-full px-4 py-3 
                    flex items-center justify-between
                    bg-slate-700 hover:bg-slate-600
                    rounded-lg transition-all
                    ${isOpen ? 'rounded-b-none' : ''}
                `}
                onClick={() => setIsOpen(!isOpen)}
            >
                <span className="font-medium">{title}</span>
                <ChevronDown
                    className={`transition-transform ${isOpen ? 'rotate-180' : ''}`}
                    size={20}
                />
            </button>
            <div
                className={`
                 transition-all
                 overflow-hidden
                    bg-slate-700/50 rounded-b-lg
                    ${isOpen ? 'p-4' : 'max-h-0'}
                `}
            >
                {children}
            </div>
        </div>
    )
}