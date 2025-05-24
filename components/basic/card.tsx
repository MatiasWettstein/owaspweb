import { AlertTriangle, Code, Lock, Shield, UserX } from "lucide-react";

interface CardProps {
    position: number;
    title: string;
    attackVector: string;
    weakness: string;
    impact: string;
    mitigationStrategies: string[];
    exampleTitle: string;
    children: React.ReactNode;
    headerColor?: string;
    goodPractices?: string[];
    positionColor?: string
}

export default function Card({ goodPractices, headerColor = 'bg-red-700', positionColor = 'text-red-700', position, title, attackVector, weakness, impact, mitigationStrategies, exampleTitle, children }: CardProps) {
    return (
        <div className="mb-12 bg-slate-800 rounded-lg overflow-hidden shadow-lg border border-slate-700">
            <div className={`${headerColor} p-4 flex items-center`}>
                <div className={`bg-white ${positionColor} h-10 w-10 rounded-full flex items-center justify-center font-bold text-xl mr-3`}>
                    {position}
                </div>
                <h3 className="text-2xl font-bold">{title}</h3>
            </div>
            <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <div className="mb-4">
                            <h4 className="font-bold text-red-400 flex items-center mb-2">
                                <UserX className="mr-2" size={18} /> Vector de ataque
                            </h4>
                            <p>{attackVector}</p>
                        </div>

                        <div className="mb-4">
                            <h4 className="font-bold text-yellow-400 flex items-center mb-2">
                                <Shield className="mr-2" size={18} /> Debilidad
                            </h4>
                            <p>{weakness}</p>
                        </div>

                        <div className="mb-4">
                            <h4 className="font-bold text-orange-400 flex items-center mb-2">
                                <AlertTriangle className="mr-2" size={18} /> Impacto
                            </h4>
                            <p>{impact}</p>
                        </div>
                    </div>

                    <div>
                        <h4 className="font-bold text-green-400 flex items-center mb-2">
                            <Lock className="mr-2" size={18} /> Estrategias de mitigación
                        </h4>
                        <ul className="list-disc pl-5 space-y-2">
                            {
                                mitigationStrategies.map((strategy, index) => (
                                    <li key={index}>{strategy}</li>
                                ))
                            }
                        </ul>
                    </div>
                </div>

                <div className="mt-6">
                    <h4 className="font-bold text-blue-400 flex items-center mb-2">
                        <Code className="mr-2" size={18} /> {exampleTitle}
                    </h4>
                    <div className="bg-slate-900 p-4 rounded-lg">
                        {children}
                    </div>
                </div>
                {goodPractices && <div className="bg-slate-700 p-4 rounded-lg mt-6">
                    <h4 className="font-bold text-indigo-300 mb-2">Buenas prácticas:</h4>
                    <ul className="list-disc pl-5 space-y-1 text-slate-300">
                        {goodPractices?.map((point, index) => (
                            <li key={index} dangerouslySetInnerHTML={{ __html: point }} />
                        ))}
                    </ul>
                </div>}
            </div>
        </div>
    )
}