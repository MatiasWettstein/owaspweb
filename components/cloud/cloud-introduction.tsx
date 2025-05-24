import { AlertTriangle, BookOpen } from "lucide-react";
import { motion } from "framer-motion"
export default function MovilIntroduction() {
    return (
        <section className="py-8 px-4 md:px-8 lg:px-16 bg-slate-800">
            <motion.div
                initial={{ opacity: 0, y: 300 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 1 }}
                className="max-w-5xl mx-auto">
                <div className="bg-slate-700 p-6 rounded-lg shadow-lg">
                    <h2 className="text-2xl font-bold mb-4 flex items-center">
                        <BookOpen className="mr-2" /> ¿Qué es OWASP?
                    </h2>
                    <p className="mb-4">
                        El <strong>Open Web Application Security Project (OWASP)</strong> es una fundación sin fines de lucro que
                        trabaja para mejorar la seguridad del software. Su lista Top 10 identifica los riesgos de seguridad más
                        críticos para las aplicaciones web y APIs y similares.
                    </p>
                    <div className="bg-cyan-900/30 border border-cyan-700 p-4 rounded-lg">
                        <h3 className="font-bold flex items-center">
                            <AlertTriangle className="mr-2" size={18} /> Riesgos específicos en entornos cloud
                        </h3>
                        <p className="mt-2">
                            Las aplicaciones cloud-native presentan desafíos particulares: configuraciones erróneas en servicios de nube, uso compartido de recursos en contenedores y orquestadores, manejo inseguro de credenciales, y una alta dependencia de componentes externos que pueden comprometer la seguridad, escalabilidad y disponibilidad del sistema.
                        </p>
                    </div>
                </div>
            </motion.div>
        </section>
    )
}