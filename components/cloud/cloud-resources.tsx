import { ArrowRight, BookOpen, Code } from "lucide-react";

export default function MovilResources() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16" >
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
                                    href="https://owasp.org/www-project-cloud-native-application-security-top-10/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP Cloud-Native Application Security Top 10
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP Kubernetes Security Cheat Sheet
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://tag-security.cncf.io/whitepaper/cloud-native-security-whitepaper-v2/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    CNCF Cloud Native Security Whitepaper v2
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
                                    href="https://kubescape.io/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Kubescape
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://github.com/tenable/terrascan"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Terrascan
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://github.com/aquasecurity/cloudsploit"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    CloudSploit
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-red-400" size={16} />
                                <a
                                    href="https://www.checkov.io/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Checkov
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    )
}