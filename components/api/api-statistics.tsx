export default function ApiStatistics() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16 bg-slate-800">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Estadísticas de Seguridad en APIs</h2>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">91%</div>
                        <p>de las organizaciones sufrieron incidentes de seguridad relacionados con APIs en 2022</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">681%</div>
                        <p>de aumento en el tráfico malicioso hacia APIs en el último año</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-red-400 mb-2">42%</div>
                        <p>de las organizaciones no tienen una estrategia de seguridad para APIs</p>
                    </div>
                </div>
            </div>
        </section>
    )
}