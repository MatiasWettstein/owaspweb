import { ArrowRight, BookOpen, Code } from "lucide-react";

export default function CriptografiaResources() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Recursos Adicionales</h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <BookOpen className="mr-2" /> Documentación y Guías
                        </h3>
                        <ul className="space-y-3">
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-indigo-400" size={16} />
                                <a
                                    href="https://csrc.nist.gov/publications/sp"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Publicaciones Especiales del NIST
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-indigo-400" size={16} />
                                <a
                                    href="https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    OWASP Cryptographic Storage Cheat Sheet
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-indigo-400" size={16} />
                                <a
                                    href="https://soatok.blog/2020/05/13/why-aes-gcm-sucks/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Soatok's Cryptography Blog
                                </a>
                            </li>
                            <li className="flex items-center">
                                <ArrowRight className="mr-2 text-indigo-400" size={16} />
                                <a
                                    href="https://cryptopals.com/"
                                    className="text-blue-400 hover:underline"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Cryptopals Crypto Challenges
                                </a>
                            </li>
                        </ul>
                    </div>

                    <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
                        <h3 className="text-xl font-bold mb-4 flex items-center">
                            <Code className="mr-2" /> Estándares y Publicaciones
                        </h3>
                        <ul className="space-y-3">
                            <li className="flex items-start">
                                <ArrowRight className="mr-2 text-indigo-400 mt-1" size={16} />
                                <div>
                                    <a
                                        href="https://tools.ietf.org/html/rfc8446"
                                        className="text-blue-400 hover:underline"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
                                    </a>
                                </div>
                            </li>
                            <li className="flex items-start">
                                <ArrowRight className="mr-2 text-indigo-400 mt-1" size={16} />
                                <div>
                                    <a
                                        href="https://tools.ietf.org/html/rfc7519"
                                        className="text-blue-400 hover:underline"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        RFC 7519: JSON Web Token (JWT)
                                    </a>
                                </div>
                            </li>
                            <li className="flex items-start">
                                <ArrowRight className="mr-2 text-indigo-400 mt-1" size={16} />
                                <div>
                                    <a
                                        href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
                                        className="text-blue-400 hover:underline"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        NIST SP 800-57: Recommendation for Key Management
                                    </a>
                                </div>
                            </li>
                            <li className="flex items-start">
                                <ArrowRight className="mr-2 text-indigo-400 mt-1" size={16} />
                                <div>
                                    <a
                                        href="https://csrc.nist.gov/projects/post-quantum-cryptography"
                                        className="text-blue-400 hover:underline"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        NIST Post-Quantum Cryptography Standardization
                                    </a>
                                </div>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    )
}