import { Server } from "lucide-react";
import { motion } from "framer-motion"
export default function ApiHeader() {
    return (
        <header className="py-12 px-4 md:px-8 lg:px-16 text-center">
            <div className="max-w-5xl mx-auto">
                <motion.div
                    initial={{ opacity: 0, scale: 0 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 1 }}
                    className="inline-block p-2 bg-lime-600 rounded-xl mb-4">
                    <Server size={48} />
                </motion.div>
                <motion.h1
                    initial={{ opacity: 0, x: 100 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 1 }}
                    className="text-4xl/normal md:text-5xl/normal font-bold mb-4 ">
                    OWASP Top 10 para APIs
                </motion.h1>
                <motion.p
                    initial={{ opacity: 0, x: -100 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 1 }}
                    className="text-xl text-slate-300 max-w-3xl mx-auto">
                    Una guía completa sobre las vulnerabilidades más críticas en APIs y cómo mitigarlas
                </motion.p>
            </div>
        </header>
    )
}