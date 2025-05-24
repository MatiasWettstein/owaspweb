export default function MovilStatistics() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16 bg-slate-800">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Estadísticas de Seguridad en Aplicaciones</h2>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">70%</div>
                        <p>de las 250 aplicaciones Android más populares filtran datos sensibles.</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">83%</div>
                        <p> de las aplicaciones tienen al menos una vulnerabilidad de seguridad.</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">70%</div>
                        <p>de las 100 principales aplicaciones financieras presentan al menos una vulnerabilidad crítica.</p>
                    </div>
                </div>
            </div>
        </section>
    )
}