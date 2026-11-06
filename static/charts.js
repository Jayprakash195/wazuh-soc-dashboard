const _charts = {};
function chart(id, type, obj, label) {
  if (_charts[id]) _charts[id].destroy();
  const el = document.getElementById(id); if (!el) return;
  const palette = ["#22d3ee", "#3b82f6", "#a78bfa", "#fbbf24", "#f87171", "#34d399", "#f472b6"];
  _charts[id] = new Chart(el, { type, data: { labels: Object.keys(obj), datasets: [{ label, data: Object.values(obj), backgroundColor: palette, borderColor: "#22d3ee" }] },
    options: { plugins: { legend: { labels: { color: "#d6e2f5" }, display: type !== "bar" && type !== "line" }, title: { display: true, text: label, color: "#d6e2f5" } },
      scales: type === "doughnut" ? {} : { x: { ticks: { color: "#8aa0c4" } }, y: { ticks: { color: "#8aa0c4", precision: 0 }, beginAtZero: true } } } });
}
