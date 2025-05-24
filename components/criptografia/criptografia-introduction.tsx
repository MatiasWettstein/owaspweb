import { AlertTriangle, BookOpen } from "lucide-react";
import { motion } from "framer-motion"
export default function CriptografiaIntroduction() {
    return (
        <section className="py-8 px-4 md:px-8 lg:px-16 bg-slate-800">
            <motion.div
                initial={{ opacity: 0, y: 300 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 1 }}
                className="max-w-5xl mx-auto">
                <div className="bg-slate-700 p-6 rounded-lg shadow-lg">
                    <h2 className="text-2xl font-bold mb-4 flex items-center">
                        <BookOpen className="mr-2" /> ¿Qué es la Criptografía Aplicada?
                    </h2>
                    <p className="mb-4">
                        La <strong>Criptografía Aplicada</strong> es la ciencia práctica de proteger la información mediante
                        técnicas matemáticas y algoritmos que transforman datos legibles en formatos aparentemente ininteligibles,
                        y viceversa. En el desarrollo de software, estas técnicas son fundamentales para garantizar la
                        confidencialidad, integridad, autenticidad y no repudio de los datos.
                    </p>
                    <div className="bg-indigo-900/30 border border-indigo-700 p-4 rounded-lg">
                        <h3 className="font-bold flex items-center">
                            <AlertTriangle className="mr-2" size={18} /> ¿Por qué es importante?
                        </h3>
                        <p className="mt-2">
                            En un mundo digital interconectado, la criptografía es la primera línea de defensa contra amenazas como
                            el robo de datos, la suplantación de identidad y la manipulación de información. Según estudios
                            recientes, el 43% de las brechas de seguridad podrían haberse evitado con una implementación adecuada de
                            técnicas criptográficas.
                        </p>
                    </div>
                </div>
            </motion.div>
        </section>
    )
}