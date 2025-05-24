export default function MovilStatistics() {
    return (
        <section className="py-12 px-4 md:px-8 lg:px-16 bg-slate-800">
            <div className="max-w-5xl mx-auto">
                <h2 className="text-3xl font-bold mb-8 text-center">Estadísticas de Seguridad en la Nube</h2>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-cyan-400 mb-2">44%</div>
                        <p>de las organizaciones informaron haber sufrido una brecha de datos en la nube en el último año</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-cyan-400 mb-2">88%</div>
                        <p>de todas las brechas de datos en la nube se deben a errores humanos</p>
                    </div>

                    <div className="bg-slate-700 p-6 rounded-lg text-center">
                        <div className="text-4xl font-bold text-cyan-400 mb-2">61%</div>
                        <p>de las organizaciones anticipan un aumento en su presupuesto de seguridad en la nube en los próximos 12 meses.</p>
                    </div>
                </div>
            </div>
        </section>
    )
}