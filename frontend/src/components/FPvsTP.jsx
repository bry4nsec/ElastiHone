import Chart from 'react-apexcharts'

const series = [
  {
    name: 'Detection Events',
    data: [
      // [FP rate, TP rate, size (severity)]
      [0.02, 0.98, 22], [0.05, 0.95, 18], [0.01, 0.97, 15],
      [0.08, 0.88, 25], [0.12, 0.72, 30], [0.03, 0.94, 20],
      [0.15, 0.65, 28], [0.04, 0.91, 17], [0.06, 0.90, 19],
      [0.02, 0.96, 14], [0.10, 0.80, 23], [0.07, 0.85, 21],
      [0.01, 0.99, 12], [0.09, 0.78, 26], [0.03, 0.93, 16],
      [0.20, 0.55, 32], [0.11, 0.76, 24], [0.04, 0.92, 13],
    ],
  },
]

const options = {
  chart: {
    type: 'bubble',
    background: 'transparent',
    toolbar: { show: false },
    zoom: { enabled: false },
  },
  colors: ['#00e5ff'],
  fill: { opacity: 0.6 },
  stroke: { width: 1, colors: ['rgba(0,229,255,0.4)'] },
  grid: {
    borderColor: 'rgba(255,255,255,0.04)',
    strokeDashArray: 3,
  },
  xaxis: {
    title: { text: 'False Positive Rate', style: { color: 'rgba(255,255,255,0.3)', fontSize: '10px' } },
    labels: { style: { colors: 'rgba(255,255,255,0.3)', fontSize: '10px' }, formatter: (v) => `${(v * 100).toFixed(0)}%` },
    min: 0,
    max: 0.25,
    tickAmount: 5,
  },
  yaxis: {
    title: { text: 'True Positive Rate', style: { color: 'rgba(255,255,255,0.3)', fontSize: '10px' } },
    labels: { style: { colors: 'rgba(255,255,255,0.3)', fontSize: '10px' }, formatter: (v) => `${(v * 100).toFixed(0)}%` },
    min: 0.5,
    max: 1.0,
    tickAmount: 5,
  },
  legend: { show: false },
  tooltip: {
    theme: 'dark',
    custom: ({ seriesIndex, dataPointIndex, w }) => {
      const point = w.config.series[seriesIndex].data[dataPointIndex]
      return `<div style="padding:8px 12px;font-size:12px;">
        <div style="color:rgba(255,255,255,0.5)">FPR: <b style="color:white">${(point[0] * 100).toFixed(1)}%</b></div>
        <div style="color:rgba(255,255,255,0.5)">TPR: <b style="color:white">${(point[1] * 100).toFixed(1)}%</b></div>
      </div>`
    },
  },
  dataLabels: { enabled: false },
  // Reference lines
  annotations: {
    yaxis: [{ y: 0.9, borderColor: 'rgba(132,204,22,0.3)', strokeDashArray: 4, label: { text: 'Target TPR', style: { color: '#84cc16', fontSize: '9px', background: 'transparent' } } }],
    xaxis: [{ x: 0.05, borderColor: 'rgba(239,68,68,0.3)', strokeDashArray: 4, label: { text: 'Max FPR', style: { color: '#ef4444', fontSize: '9px', background: 'transparent' } } }],
  },
}

export default function FPvsTP() {
  return (
    <div className="glass-card p-5">
      <h3 className="text-sm font-semibold text-white mb-2">FP vs TP Distribution</h3>
      <Chart options={options} series={series} type="bubble" height={230} />
    </div>
  )
}
