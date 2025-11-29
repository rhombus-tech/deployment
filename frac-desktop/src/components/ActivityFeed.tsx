import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { CheckCircle2, TrendingUp } from 'lucide-react'

interface ActivityEntry {
  timestamp: number
  proof_type: string
  task_id: string
  reward: number
  block_number?: number
}

export function ActivityFeed() {
  const [activity, setActivity] = useState<ActivityEntry[]>([])

  useEffect(() => {
    const loadActivity = async () => {
      try {
        const data = await invoke<ActivityEntry[]>('get_activity')
        setActivity(data)
      } catch (error) {
        console.error('Failed to load activity:', error)
      }
    }

    loadActivity()
    const interval = setInterval(loadActivity, 5000) // Update every 5 seconds

    return () => clearInterval(interval)
  }, [])

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp * 1000)
    return date.toLocaleTimeString()
  }

  return (
    <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-xl p-6">
      <h3 className="text-white font-semibold mb-4 flex items-center space-x-2">
        <TrendingUp className="w-5 h-5" />
        <span>Recent Activity</span>
      </h3>

      <div className="space-y-3">
        {activity.length === 0 ? (
          <p className="text-slate-400 text-sm text-center py-8">
            No activity yet. Start proving to see your earnings!
          </p>
        ) : (
          activity.slice(0, 10).map((entry, index) => (
            <div
              key={index}
              className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg hover:bg-slate-900/70 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <CheckCircle2 className="w-5 h-5 text-green-400" />
                <div>
                  <p className="text-white font-medium">
                    {entry.proof_type}
                  </p>
                  <p className="text-slate-400 text-xs">
                    {formatTime(entry.timestamp)}
                    {entry.block_number && ` • Block #${entry.block_number}`}
                  </p>
                </div>
              </div>
              <span className="text-green-400 font-semibold">
                +{entry.reward} FRAC
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
