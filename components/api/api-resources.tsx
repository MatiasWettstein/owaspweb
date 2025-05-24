import { ArrowRight, BookOpen, Code } from "lucide-react";

export default function ApiResources() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Recursos Adicionales</h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <BookOpen className="mr-2" /> Documentación Oficial
                        </h3>
                        <ul className="space-y-3">
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://owasp.org/API-Security/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP API Security Project
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP REST Security Cheat Sheet
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://github.com/OWASP/API-Security"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Repositorio GitHub de OWASP API Security
                                </a>
                            </li>
                        </ul>
                    </div>

                    <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <Code className="mr-2" /> Herramientas de Seguridad
                        </h3>
                        <ul className="space-y-3">
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://owasp.org/www-project-zap/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP ZAP (Zed Attack Proxy)
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://portswigger.net/burp"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Burp Suite
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://github.com/OWASP/APICheck"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP APICheck
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    )
}