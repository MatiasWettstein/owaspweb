export default function PlatformTabs({ getPlatform, setPlatform, name }: { getPlatform: (e: string) => string, setPlatform: (e: string, y: string) => void, name: string }) {
    return (
        <div className="flex mb-4 border-b border-slate-700">
            <button
                className={`px-4 py-2 ${getPlatform(name) === "android"
                    ? "bg-purple-700 text-white"
                    : "bg-slate-800 text-slate-300"
                    } rounded-t-md mr-1`}
                onClick={() => setPlatform(name, "android")}
            >
                Android
            </button>
            <button
                className={`px-4 py-2 ${getPlatform(name) === "ios"
                    ? "bg-purple-700 text-white"
                    : "bg-slate-800 text-slate-300"
                    } rounded-t-md mr-1`}
                onClick={() => setPlatform(name, "ios")}
            >
                iOS
            </button>
            <button
                className={`px-4 py-2 ${getPlatform(name) === "reactnative"
                    ? "bg-purple-700 text-white"
                    : "bg-slate-800 text-slate-300"
                    } rounded-t-md`}
                onClick={() => setPlatform(name, "reactnative")}
            >
                React Native
            </button>
        </div>
    )
}