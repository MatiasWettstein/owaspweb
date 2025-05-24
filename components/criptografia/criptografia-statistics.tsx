export default function CriptografiaStatistics() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16 bg-slate-800 rounded-lg mb-16">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Estadísticas relacionadas a la Criptografía</h2>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-indigo-400 mb-2">94%</div>
                        <p>
                            de las organizaciones han experimentado una brecha de seguridad relacionada con criptografía débil
                        </p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-indigo-400 mb-2">43%</div>
                        <p>
                            de las brechas de seguridad podrían haberse evitado con implementaciones criptográficas adecuadas
                        </p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-indigo-400 mb-2">67%</div>
                        <p>de las organizaciones no tienen un plan de migración a criptografía post-cuántica</p>
                    </div>
                </div>
            </div>
        </section>
    )
}