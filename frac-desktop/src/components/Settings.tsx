import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { Settings as SettingsIcon, Save } from 'lucide-react'

interface SettingsProps {
  walletAddress: string
}

export function Settings({ walletAddress }: SettingsProps) {
  const [enableVulnAnalysis, setEnableVulnAnalysis] = useState(true)
  const [autoPauseGaming, setAutoPauseGaming] = useState(true)
  const [autoPauseBattery, setAutoPauseBattery] = useState(true)
  const [isSaving, setIsSaving] = useState(false)

  const handleSave = async () => {
    setIsSaving(true)
    try {
      await invoke('update_settings', {
        enableVulnerabilityAnalysis: enableVulnAnalysis,
        autoPauseGaming,
        autoPauseBattery
      })
      alert('Settings saved successfully!')
    } catch (error) {
      alert(`Failed to save settings: ${error}`)
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-2xl p-8">
        <h2 className="text-2xl font-bold text-white mb-6 flex items-center space-x-2">
          <SettingsIcon className="w-6 h-6" />
          <span>Settings</span>
        </h2>

        <div className="space-y-6">
          {/* Wallet Address */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              💰 Wallet Address
            </label>
            <div className="px-4 py-3 bg-slate-900/50 border border-slate-600 rounded-lg text-slate-400">
              {walletAddress}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Your earnings will be sent to this address
            </p>
          </div>

          {/* Performance Mode */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">
              🚀 Security Mode
            </label>
            <div className="space-y-2">
              <label className="flex items-center space-x-3 p-3 bg-slate-900/30 rounded-lg cursor-pointer hover:bg-slate-900/50">
                <input
                  type="checkbox"
                  checked={enableVulnAnalysis}
                  onChange={(e) => setEnableVulnAnalysis(e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 bg-slate-900 text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <p className="text-white font-medium">Enable vulnerability analysis</p>
                  <p className="text-xs text-slate-400">
                    Full security checks (~100-200ms per proof)
                  </p>
                </div>
              </label>
            </div>
            {!enableVulnAnalysis && (
              <p className="text-xs text-yellow-400 mt-2">
                ⚠️ Fast mode: 10x faster but skips security checks
              </p>
            )}
          </div>

          {/* Auto-Pause */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">
              🎮 Auto-Pause
            </label>
            <div className="space-y-2">
              <label className="flex items-center space-x-3 p-3 bg-slate-900/30 rounded-lg cursor-pointer hover:bg-slate-900/50">
                <input
                  type="checkbox"
                  checked={autoPauseGaming}
                  onChange={(e) => setAutoPauseGaming(e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 bg-slate-900 text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <p className="text-white font-medium">When gaming detected</p>
                  <p className="text-xs text-slate-400">
                    Pause proving when high GPU usage is detected
                  </p>
                </div>
              </label>

              <label className="flex items-center space-x-3 p-3 bg-slate-900/30 rounded-lg cursor-pointer hover:bg-slate-900/50">
                <input
                  type="checkbox"
                  checked={autoPauseBattery}
                  onChange={(e) => setAutoPauseBattery(e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 bg-slate-900 text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <p className="text-white font-medium">When battery &lt;20%</p>
                  <p className="text-xs text-slate-400">
                    Save battery when running low
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Save Button */}
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:opacity-50 text-white font-semibold rounded-lg transition-all flex items-center justify-center space-x-2"
          >
            <Save className="w-5 h-5" />
            <span>{isSaving ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {/* Stats Info */}
      <div className="mt-6 bg-slate-800/30 border border-slate-700/50 rounded-xl p-6">
        <h3 className="text-white font-semibold mb-4">💡 Performance Tips</h3>
        <ul className="space-y-2 text-sm text-slate-400">
          <li>• Keep the app running 24/7 for maximum earnings</li>
          <li>• Enable security mode for trusted contracts</li>
          <li>• Fast mode gives 10x speed but skips vulnerability checks</li>
          <li>• First 1000 users get permanent 2x rewards</li>
        </ul>
      </div>
    </div>
  )
}
