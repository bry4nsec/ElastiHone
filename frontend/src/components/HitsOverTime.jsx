import Chart from 'react-apexcharts'

const series = [
  {
    name: 'Current Rule',
    data: [142, 158, 133, 167, 145, 189, 201, 176, 154, 198, 210, 185, 169, 224, 197, 212, 188, 165, 179, 193, 207, 215, 228, 195],
  },
  {
    name: 'Optimized Rule',
    data: [12, 15, 9, 18, 14, 22, 19, 16, 11, 20, 17, 13, 14, 21, 16, 18, 15, 12, 14, 16, 19, 17, 20, 15],
  },
]

const options = {
  chart: {
    type: 'area',
    background: 'transparent',
    toolbar: { show: false },
    zoom: { enabled: false },
    animations: {
      enabled: true,
      easing: 'easeinout',
      speed: 1000,
    },
  },
  colors: ['rgba(168, 85, 247, 0.8)', 'rgba(0, 229, 255, 0.8)'],
  fill: {
    type: 'gradient',
    gradient: {
      shadeIntensity: 1,
      opacityFrom: 0.25,
      opacityTo: 0.02,
      stops: [0, 100],
    },
  },
  stroke: { curve: 'smooth', width: 2.5 },
  grid: {
    borderColor: 'rgba(255,255,255,0.04)',
    strokeDashArray: 3,
    xaxis: { lines: { show: false } },
  },
  xaxis: {
    categories: Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`),
    labels: {
      style: { colors: 'rgba(255,255,255,0.3)', fontSize: '10px' },
      rotate: 0,
      hideOverlappingLabels: true,
    },
    axisBorder: { show: false },
    axisTicks: { show: false },
  },
  yaxis: {
    labels: { style: { colors: 'rgba(255,255,255,0.3)', fontSize: '10px' } },
  },
  legend: {
    position: 'top',
    horizontalAlign: 'right',
    labels: { colors: 'rgba(255,255,255,0.5)' },
    fontSize: '11px',
    markers: { size: 6, offsetX: -4 },
  },
  tooltip: {
    theme: 'dark',
    style: { fontSize: '12px' },
  },
  dataLabels: { enabled: false },
}

export default function HitsOverTime() {
  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-white">Rule Hits Over Time</h3>
        <div className="flex gap-2">
          {['24h', '7d', '30d'].map((period) => (
            <button
              key={period}
              className={`px-2.5 py-1 rounded-md text-[10px] font-semibold uppercase tracking-wider transition-all cursor-pointer ${
                period === '24h'
                  ? 'bg-cyan-glow/15 text-cyan-glow border border-cyan-glow/20'
                  : 'text-white/30 hover:text-white/50 border border-transparent'
              }`}
            >
              {period}
            </button>
          ))}
        </div>
      </div>
      <Chart options={options} series={series} type="area" height={220} />
    </div>
  )
}
