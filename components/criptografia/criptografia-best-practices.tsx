import { Key, RefreshCw, Server, Shield, Lock } from "lucide-react";

export default function CriptografiaBestPractices() {
    return (
        <section className="mb-16">
            <h2 className="text-3xl font-bold mb-8 flex items-center">
                <Lock className="mr-3" /> Mejores Prácticas en Criptografía
            </h2>

            <div className="bg-slate-800 rounded-lg overflow-hidden shadow-lg border border-slate-700 mb-8">
                <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <h3 className="text-xl font-bold mb-4 text-indigo-400 flex items-center">
                                <Shield className="mr-2" /> Principios Fundamentales
                            </h3>
                            <ul className="space-y-3">
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">No implementes tu propia criptografía:</strong> Utiliza
                                        bibliotecas probadas y auditadas por expertos.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Mantén el software actualizado:</strong> Las
                                        actualizaciones suelen incluir parches de seguridad críticos.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Principio de Kerckhoffs:</strong> La seguridad debe
                                        depender solo del secreto de la clave, no del algoritmo.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Defensa en profundidad:</strong> Implementa múltiples
                                        capas de protección criptográfica.
                                    </div>
                                </li>
                            </ul>
                        </div>

                        <div>
                            <h3 className="text-xl font-bold mb-4 text-indigo-400 flex items-center">
                                <Key className="mr-2" /> Gestión de Claves
                            </h3>
                            <ul className="space-y-3">
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Generación segura:</strong> Utiliza generadores de números
                                        aleatorios criptográficamente seguros (CSPRNG).
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Almacenamiento protegido:</strong> Usa módulos de
                                        seguridad hardware (HSM) o enclaves seguros cuando sea posible.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Rotación periódica:</strong> Cambia las claves
                                        regularmente para limitar el impacto de posibles compromisos.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Plan de recuperación:</strong> Implementa procedimientos
                                        para recuperación de claves en caso de pérdida.
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </div>

                    <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <h3 className="text-xl font-bold mb-4 text-indigo-400 flex items-center">
                                <Server className="mr-2" /> Implementación Segura
                            </h3>
                            <ul className="space-y-3">
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Validación de entradas:</strong> Verifica y sanitiza todas
                                        las entradas antes de procesarlas criptográficamente.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Protección contra ataques de canal lateral:</strong> Evita
                                        fugas de información a través de tiempos de ejecución o consumo de energía.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Manejo de errores seguro:</strong> No reveles información
                                        sensible en mensajes de error.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Auditoría y logging:</strong> Registra eventos
                                        criptográficos importantes sin exponer datos sensibles.
                                    </div>
                                </li>
                            </ul>
                        </div>

                        <div>
                            <h3 className="text-xl font-bold mb-4 text-indigo-400 flex items-center">
                                <RefreshCw className="mr-2" /> Adaptabilidad y Futuro
                            </h3>
                            <ul className="space-y-3">
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Agilidad criptográfica:</strong> Diseña sistemas que
                                        permitan cambiar algoritmos sin reescribir toda la aplicación.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Preparación post-cuántica:</strong> Comienza a planificar
                                        la migración a algoritmos resistentes a computación cuántica.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Seguimiento de estándares:</strong> Mantente al día con
                                        las recomendaciones de NIST, IETF y otras organizaciones.
                                    </div>
                                </li>
                                <li className="flex items-start">
                                    <div className="bg-indigo-700 p-1 rounded-full mr-2 mt-1">
                                        <span className="block h-2 w-2 rounded-full bg-white"></span>
                                    </div>
                                    <div>
                                        <strong className="text-indigo-300">Evaluación continua:</strong> Realiza auditorías de
                                        seguridad y pruebas de penetración regularmente.
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    )
}