import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

interface EarningsData {
  hour: number
  earnings: number
}

export function EarningsChart() {
  const [data, setData] = useState<EarningsData[]>([])

  useEffect(() => {
    const loadData = async () => {
      try {
        const chartData = await invoke<EarningsData[]>('get_earnings_chart')
        setData(chartData)
      } catch (error) {
        console.error('Failed to load chart data:', error)
      }
    }

    loadData()
    const interval = setInterval(loadData, 60000) // Update every minute

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorEarnings" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#a78bfa" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#a78bfa" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <XAxis 
            dataKey="hour"
            stroke="#64748b"
            tick={{ fill: '#94a3b8' }}
            tickFormatter={(value) => {
              const date = new Date(value * 3600 * 1000)
              return date.getHours() + ':00'
            }}
          />
          <YAxis 
            stroke="#64748b"
            tick={{ fill: '#94a3b8' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#fff'
            }}
            formatter={(value: number) => [`${value} FRAC`, 'Earned']}
          />
          <Area
            type="monotone"
            dataKey="earnings"
            stroke="#a78bfa"
            fillOpacity={1}
            fill="url(#colorEarnings)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
