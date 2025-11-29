import { Play, Pause, TrendingUp, Award, Zap } from 'lucide-react'
import { EarningsChart } from './EarningsChart'
import { ActivityFeed } from './ActivityFeed'
import { motion } from 'framer-motion'

interface DashboardProps {
  stats: {
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
  onStartStop: () => void
}

export function Dashboard({ stats, onStartStop }: DashboardProps) {
  const formatNumber = (num: number) => {
    return new Intl.NumberFormat('en-US').format(num)
  }

  const formatCurrency = (num: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(num)
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Genesis NFT Banner */}
      {stats.genesis_nft_id && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gradient-to-r from-yellow-600/20 to-orange-600/20 border border-yellow-500/50 rounded-xl p-4"
        >
          <div className="flex items-center space-x-3">
            <Award className="w-6 h-6 text-yellow-400" />
            <div>
              <h3 className="text-yellow-400 font-semibold">
                Genesis NFT #{stats.genesis_nft_id}
              </h3>
              <p className="text-yellow-200/70 text-sm">
                2x Rewards Forever • Zero Fees • Founding Member
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Main Earnings Display - Fractal Border */}
      <div className="relative">
        {/* Fractal Corner Decorations */}
        <div className="absolute -top-2 -left-2 w-8 h-8 border-l-2 border-t-2 border-purple-500/50 rounded-tl-2xl"></div>
        <div className="absolute -top-2 -right-2 w-8 h-8 border-r-2 border-t-2 border-purple-500/50 rounded-tr-2xl"></div>
        <div className="absolute -bottom-2 -left-2 w-8 h-8 border-l-2 border-b-2 border-purple-500/50 rounded-bl-2xl"></div>
        <div className="absolute -bottom-2 -right-2 w-8 h-8 border-r-2 border-b-2 border-purple-500/50 rounded-br-2xl"></div>
        
        <div className="bg-slate-900/60 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-8 relative overflow-hidden">
          {/* Phi Spiral Overlay */}
          <div className="absolute top-0 right-0 w-64 h-64 opacity-5 pointer-events-none">
            <svg viewBox="0 0 200 200" className="w-full h-full">
              <path d="M 100 100 Q 161.8 100 161.8 38.2 Q 161.8 -23.6 100 -23.6 Q 38.2 -23.6 38.2 38.2 Q 38.2 100 100 100" 
                    stroke="#a78bfa" strokeWidth="2" fill="none"/>
            </svg>
          </div>
          
          <div className="text-center mb-6 relative z-10">
            <p className="text-slate-400 text-sm mb-2">Total Earned</p>
            <h2 className="text-5xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent mb-2">
              {formatNumber(stats.total_earned)} FRAC
            </h2>
            <p className="text-2xl text-purple-400">
              ≈ {formatCurrency(stats.total_earned_usd)}
            </p>
          </div>

          <EarningsChart />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Today"
          value={`+${formatNumber(stats.today_earned)}`}
          subtitle="FRAC"
          icon={<TrendingUp className="w-5 h-5" />}
          color="text-green-400"
        />
        <StatCard
          label="This Week"
          value={`+${formatNumber(stats.week_earned)}`}
          subtitle="FRAC"
          icon={<Zap className="w-5 h-5" />}
          color="text-blue-400"
        />
        <StatCard
          label="Total Proofs"
          value={formatNumber(stats.total_proofs)}
          subtitle={`${stats.proofs_today} today`}
          icon={<Award className="w-5 h-5" />}
          color="text-purple-400"
        />
        <StatCard
          label="Staked"
          value={formatNumber(stats.staked_amount)}
          subtitle="FRAC"
          icon={<TrendingUp className="w-5 h-5" />}
          color="text-yellow-400"
        />
      </div>

      {/* Status & Control */}
      <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-xl p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className={`w-3 h-3 rounded-full ${stats.is_running ? 'bg-green-400 animate-pulse' : 'bg-slate-500'}`} />
            <div>
              <p className="text-white font-semibold">
                {stats.is_running ? 'Proving' : 'Paused'}
              </p>
              <p className="text-slate-400 text-sm">
                {stats.is_running 
                  ? `${stats.proofs_per_minute.toFixed(1)} proofs/min • Epoch ${stats.current_epoch} (${stats.epoch_multiplier}x)`
                  : 'Click start to begin earning'}
              </p>
            </div>
          </div>

          <button
            onClick={onStartStop}
            className={`px-8 py-3 rounded-lg font-semibold flex items-center space-x-2 transition-all ${
              stats.is_running
                ? 'bg-red-600 hover:bg-red-500 text-white'
                : 'bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white'
            }`}
          >
            {stats.is_running ? (
              <>
                <Pause className="w-5 h-5" />
                <span>Pause</span>
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                <span>Start Proving</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Activity Feed */}
      <ActivityFeed />
    </div>
  )
}

interface StatCardProps {
  label: string
  value: string
  subtitle: string
  icon: React.ReactNode
  color: string
}

function StatCard({ label, value, subtitle, icon, color }: StatCardProps) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-slate-400 text-sm">{label}</span>
        <span className={color}>{icon}</span>
      </div>
      <p className="text-2xl font-bold text-white mb-1">{value}</p>
      <p className="text-slate-500 text-xs">{subtitle}</p>
    </div>
  )
}
