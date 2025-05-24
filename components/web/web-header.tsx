import { Laptop } from "lucide-react";
import { motion } from "framer-motion"

export default function WebHeader() {
    return (
        <header className="py-12 px-4 md:px-8 lg:px-16 text-center">
            <div className="max-w-5xl mx-auto">
                <motion.div
                    initial={{ opacity: 0, scale: 0 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 1 }}
                    className="inline-block p-2 bg-red-600 rounded-xl mb-4">
                    <Laptop size={48} />
                </motion.div>
                <motion.h1
                    initial={{ opacity: 0, x: -100 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 1 }}
                    className="text-4xl/normal md:text-5xl/normal font-bold mb-4 ">OWASP Top 10 para Aplicaciones Web</motion.h1>
                <motion.p
                    initial={{ opacity: 0, x: 100 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 1 }}
                    className="text-xl text-slate-300 max-w-3xl mx-auto">
                    Una guía completa sobre las vulnerabilidades más críticas en aplicaciones web y cómo mitigarlas
                </motion.p>
            </div>
        </header>
    )
}