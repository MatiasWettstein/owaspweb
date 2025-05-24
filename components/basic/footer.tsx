import { Github } from 'lucide-react';

export default function Footer() {
    return (
        <footer className="py-8 px-4 md:px-8 lg:px-16 bg-slate-900/30 text-center z-10 relative">
            <div className="max-w-5xl mx-auto">
                <p className="text-slate-400">Basado en la documentación oficial de OWASP y sitios especializados en seguridad</p>
                <p className="text-slate-400 text-xs mt-2">* Todos los ejemplos presentados en esta página son a modo ilustrativo para explicar los conceptos abordados</p>
                <p className="text-slate-400 text-xs mt-2">
                    <a href="https://github.com/MatiasWettstein/owaspweb" target="_blank" rel="noopener noreferrer" className="hover:text-slate-200 inline-flex items-center">
                        <Github className="mr-2 h-4 w-4" />
                        Repositorio en GitHub
                    </a>
                </p>
            </div>
        </footer>
    )
}