import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { Dashboard } from './components/Dashboard'
import { Settings } from './components/Settings'
import { Settings as SettingsIcon, TrendingUp } from 'lucide-react'

interface DashboardStats {
  is_running: boolean
  total_earned: number
  total_earned_usd: number
  today_earned: number
  week_earned: number
  total_proofs: number
  proofs_today: number
  proofs_per_minute: number
  genesis_nft_id: number | null
  staked_amount: number
  current_epoch: number
  epoch_multiplier: number
}

function App() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [currentView, setCurrentView] = useState<'dashboard' | 'settings'>('dashboard')
  const [walletAddress, setWalletAddress] = useState('')
  const [isInitialized, setIsInitialized] = useState(false)

  useEffect(() => {
    // Load stats every 2 seconds
    const interval = setInterval(async () => {
      if (isInitialized) {
        try {
          const newStats = await invoke<DashboardStats>('get_stats')
          setStats(newStats)
        } catch (error) {
          console.error('Failed to get stats:', error)
        }
      }
    }, 2000)

    return () => clearInterval(interval)
  }, [isInitialized])

  const handleInitialize = async () => {
    if (!walletAddress) {
      alert('Please enter your wallet address')
      return
    }

    try {
      await invoke('initialize_prover', {
        walletAddress,
        rpcUrl: 'https://eth.llamarpc.com'
      })
      setIsInitialized(true)
    } catch (error) {
      alert(`Failed to initialize: ${error}`)
    }
  }

  const handleStartStop = async () => {
    try {
      if (stats?.is_running) {
        await invoke('stop_proving')
      } else {
        await invoke('start_proving')
      }
    } catch (error) {
      alert(`Failed to ${stats?.is_running ? 'stop' : 'start'}: ${error}`)
    }
  }

  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-2xl p-8 max-w-md w-full">
          <div className="text-center mb-8">
            <div className="text-6xl mb-4">💎</div>
            <h1 className="text-3xl font-bold text-white mb-2">FRAC Prover</h1>
            <p className="text-slate-400">Start earning crypto rewards</p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Wallet Address
              </label>
              <input
                type="text"
                value={walletAddress}
                onChange={(e) => setWalletAddress(e.target.value)}
                placeholder="0x..."
                className="w-full px-4 py-3 bg-slate-900/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>

            <button
              onClick={handleInitialize}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold rounded-lg transition-all"
            >
              Start Earning
            </button>

            <p className="text-xs text-slate-400 text-center">
              First 1000 users get 2x rewards FOREVER
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 relative overflow-hidden">
      {/* Fractal Background */}
      <div className="fixed inset-0 pointer-events-none">
        <svg className="w-full h-full opacity-10" viewBox="0 0 1000 1000">
          {/* Golden Spiral */}
          <path d="M 500 500 Q 600 500 600 400 Q 600 300 500 300 Q 400 300 400 400 Q 400 500 500 500" 
                stroke="url(#fractal-gradient)" strokeWidth="2" fill="none" opacity="0.6"/>
          <path d="M 500 500 Q 700 500 700 300 Q 700 100 500 100 Q 300 100 300 300 Q 300 500 500 500" 
                stroke="url(#fractal-gradient)" strokeWidth="2" fill="none" opacity="0.4"/>
          <path d="M 500 500 Q 800 500 800 200 Q 800 -100 500 -100 Q 200 -100 200 200 Q 200 500 500 500" 
                stroke="url(#fractal-gradient)" strokeWidth="2" fill="none" opacity="0.2"/>
          
          {/* Recursive Triangles */}
          <g transform="translate(250, 750)">
            <polygon points="0,0 50,-87 100,0" fill="none" stroke="url(#fractal-gradient)" strokeWidth="1" opacity="0.3"/>
            <polygon points="25,-43 37.5,-65 50,-43" fill="none" stroke="url(#fractal-gradient)" strokeWidth="0.5" opacity="0.4"/>
            <polygon points="12.5,-21.5 18.75,-32.5 25,-21.5" fill="none" stroke="url(#fractal-gradient)" strokeWidth="0.3" opacity="0.5"/>
          </g>
          
          {/* φ-based circles */}
          <circle cx="500" cy="500" r="50" fill="none" stroke="url(#fractal-gradient)" strokeWidth="1" opacity="0.2"/>
          <circle cx="500" cy="500" r="80.9" fill="none" stroke="url(#fractal-gradient)" strokeWidth="1" opacity="0.2"/>
          <circle cx="500" cy="500" r="130.9" fill="none" stroke="url(#fractal-gradient)" strokeWidth="1" opacity="0.2"/>
          <circle cx="500" cy="500" r="211.8" fill="none" stroke="url(#fractal-gradient)" strokeWidth="1" opacity="0.2"/>
          
          <defs>
            <linearGradient id="fractal-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#a78bfa" />
              <stop offset="50%" stopColor="#ec4899" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      {/* Navigation */}
      <nav className="border-b border-purple-500/20 backdrop-blur-xl bg-slate-900/40 relative z-10">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="text-3xl">💎</span>
            <div>
              <h1 className="text-xl font-bold text-white">FRAC Prover</h1>
              <p className="text-xs text-slate-400">Earning rewards 24/7</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentView('dashboard')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
                currentView === 'dashboard'
                  ? 'bg-purple-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <TrendingUp className="w-4 h-4" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setCurrentView('settings')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
                currentView === 'settings'
                  ? 'bg-purple-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <SettingsIcon className="w-4 h-4" />
              <span>Settings</span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="p-6">
        {currentView === 'dashboard' && stats && (
          <Dashboard stats={stats} onStartStop={handleStartStop} />
        )}
        {currentView === 'settings' && (
          <Settings walletAddress={walletAddress} />
        )}
      </main>
    </div>
  )
}

export default App
