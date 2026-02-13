/**
 * Backend energy data: fetch from MoSPI and aggregate by commodity.
 * Real data only; used for LinkedIn post generation and sector alerts.
 */

const MOSPI_BASE = process.env.MOSPI_API_BASE || "https://api.mospi.gov.in/api";
const ENERGY_BASE = `${MOSPI_BASE}/energy/getEnergyRecords`;

const FETCH_RETRIES = 3;
const FETCH_RETRY_DELAY_MS = 1500;

async function fetchWithRetry(url) {
  let lastErr;
  for (let attempt = 1; attempt <= FETCH_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 25000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      if (attempt < FETCH_RETRIES) await new Promise((r) => setTimeout(r, FETCH_RETRY_DELAY_MS));
    }
  }
  throw lastErr;
}

function parseFiscalYear(yearStr) {
  if (!yearStr) return NaN;
  const match = /^(\d{4})/.exec(String(yearStr));
  return match ? Number(match[1]) : NaN;
}

export async function fetchSupplyRecords() {
  const url = `${ENERGY_BASE}?indicator_code=${encodeURIComponent("Energy Balance ( in PetaJoules )")}&use_of_energy_balance_code=Supply&Format=JSON&limit=555`;
  const json = await fetchWithRetry(url);
  return json.data || [];
}

export async function fetchConsumptionRecords() {
  const url = `${ENERGY_BASE}?indicator_code=${encodeURIComponent("Energy Balance ( in KToE )")}&use_of_energy_balance_code=Consumption&Format=JSON&limit=7000`;
  const json = await fetchWithRetry(url);
  return json.data || [];
}

function aggregateSupplyByCommodity(records) {
  const byCommodity = {};
  for (const r of records) {
    const sector = (r.end_use_sector || "").toLowerCase();
    const commodity = r.energy_commodities || "Other";
    if (!byCommodity[commodity]) byCommodity[commodity] = { production: 0, imports: 0, exports: 0, supply: 0, stockChanges: 0 };
    const val = Number(r.value) || 0;
    if (sector.includes("production")) {
      byCommodity[commodity].production += val;
    } else if (sector.includes("imports")) {
      byCommodity[commodity].imports += val;
    } else if (sector.includes("exports")) {
      byCommodity[commodity].exports += Math.abs(val);
    } else if (sector.includes("stock")) {
      byCommodity[commodity].stockChanges += val;
    } else if (sector.includes("total primary")) {
      byCommodity[commodity].supply += val;
    }
  }
  return byCommodity;
}

function aggregateConsumptionByCommodity(records) {
  const byCommodity = {};
  const bySectorByCommodity = {};
  for (const r of records) {
    const sector = (r.end_use_sector || "").toLowerCase();
    const commodity = r.energy_commodities || "Other";
    const val = Number(r.value) || 0;
    if (sector === "final consumption") {
      byCommodity[commodity] = (byCommodity[commodity] || 0) + val;
    }
    if (sector === "final consumption" || sector === "industry" || sector === "transport" || sector.includes("residential") || r.end_use_sub_sector) {
      const sectorName = r.end_use_sub_sector || (sector === "industry" ? "Industry" : sector === "transport" ? "Transport" : sector.includes("residential") ? "Residential" : sector);
      if (!bySectorByCommodity[commodity]) bySectorByCommodity[commodity] = {};
      bySectorByCommodity[commodity][sectorName] = (bySectorByCommodity[commodity][sectorName] || 0) + val;
    }
  }
  return { byCommodity, bySectorByCommodity };
}

/** Build by-year supply/consumption/ratio for one commodity (from raw supply + consumption records). */
function buildCommodityAnalysis(supplyRecords, consRecords, commodityName) {
  const byYear = new Map();
  const addSupply = (r) => {
    if ((r.energy_commodities || "Other") !== commodityName) return;
    const year = parseFiscalYear(r.year);
    const val = Number(r.value) || 0;
    const sector = (r.end_use_sector || "").toLowerCase();
    if (!year || !Number.isFinite(year)) return;
    let entry = byYear.get(year);
    if (!entry) entry = { year, fiscalYear: r.year, supply: 0, consumption: 0 };
    if (sector.includes("total primary")) entry.supply += val;
    byYear.set(year, entry);
  };
  const addConsumption = (r) => {
    if ((r.energy_commodities || "Other") !== commodityName) return;
    const year = parseFiscalYear(r.year);
    const val = Number(r.value) || 0;
    const sector = (r.end_use_sector || "").toLowerCase();
    if (!year || !Number.isFinite(year)) return;
    let entry = byYear.get(year);
    if (!entry) entry = { year, fiscalYear: r.year, supply: 0, consumption: 0 };
    if (sector === "final consumption") entry.consumption += val;
    byYear.set(year, entry);
  };
  supplyRecords.forEach(addSupply);
  consRecords.forEach(addConsumption);
  const byYearArr = Array.from(byYear.values())
    .map((row) => ({ ...row, ratio: row.consumption === 0 ? null : row.supply / row.consumption }))
    .sort((a, b) => a.year - b.year);
  const latest = byYearArr[byYearArr.length - 1] || null;
  return { byYear: byYearArr, latest };
}

function linearRegression(points) {
  const n = points.length;
  if (n < 2) return null;
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  for (const p of points) {
    sumX += p.x;
    sumY += p.y;
    sumXY += p.x * p.y;
    sumX2 += p.x * p.x;
  }
  const denom = n * sumX2 - sumX * sumX;
  if (Math.abs(denom) < 1e-10) return null;
  const slope = (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slope * sumX) / n;
  return { slope, intercept, predict: (x) => slope * x + intercept };
}

/** Build forecast (projected ratio, next year, status) for a commodity. */
function buildCommodityForecast(analysis) {
  const years = analysis.byYear.slice(-10);
  if (years.length < 2) return null;
  const supPoints = years.map((r) => ({ x: r.year, y: r.supply }));
  const conPoints = years.map((r) => ({ x: r.year, y: r.consumption }));
  const supModel = linearRegression(supPoints);
  const conModel = linearRegression(conPoints);
  const lastYear = years[years.length - 1].year;
  const nextYear = lastYear + 1;
  const projectedSupply = supModel ? supModel.predict(nextYear) : null;
  const projectedConsumption = conModel ? conModel.predict(nextYear) : null;
  const projectedRatio =
    projectedSupply != null && projectedConsumption != null && projectedConsumption !== 0
      ? projectedSupply / projectedConsumption
      : null;
  const status = projectedRatio != null && projectedRatio < 0.95 ? "pressure" : projectedRatio != null && projectedRatio > 1.05 ? "surplus" : "stable";
  return { nextYear, projectedSupply, projectedConsumption, projectedRatio, status };
}

/** Risk score 0-100 and alerts for a commodity (deficit=high, decline=medium, volatility=medium). */
function getCommodityRisk(commodityName, analysis, forecast) {
  const byYear = analysis?.byYear ?? [];
  const latest = analysis?.latest;
  const ratio = latest?.ratio ?? forecast?.projectedRatio ?? null;
  let score = 0;
  const reasons = [];
  if (ratio != null && ratio < 1) {
    score = Math.max(score, 80);
    reasons.push("Supply deficit (ratio < 1)");
  }
  const last5 = byYear.slice(-5);
  if (last5.length >= 2) {
    const firstSupply = last5[0].supply;
    const lastSupply = last5[last5.length - 1].supply;
    if (firstSupply > 0 && lastSupply < firstSupply) {
      score = Math.max(score, 50);
      reasons.push("Declining supply trend");
    }
  }
  for (let i = 1; i < byYear.length; i++) {
    const prev = byYear[i - 1];
    const curr = byYear[i];
    if (prev.supply > 0) {
      const pct = Math.abs((curr.supply - prev.supply) / prev.supply) * 100;
      if (pct >= 15) {
        score = Math.max(score, 45);
        reasons.push("High YoY volatility");
        break;
      }
    }
  }
  return { riskScore: Math.min(100, score), reasons };
}

/** Get top N consuming sectors for a commodity by share. */
function getTopConsumingSectors(bySectorByCommodity, commodityName, n = 2) {
  const sectorTotals = bySectorByCommodity[commodityName] || {};
  const total = Object.values(sectorTotals).reduce((a, b) => a + b, 0);
  if (total === 0) return [];
  const entries = Object.entries(sectorTotals)
    .map(([name, val]) => ({ name, value: val, sharePct: (val / total) * 100 }))
    .sort((a, b) => b.value - a.value);
  return entries.slice(0, n);
}

/**
 * Fetch live data for one commodity and return stats for LinkedIn + alerts.
 * commodityId can be display name (e.g. "Coal") matching API energy_commodities.
 */
export async function fetchCommodityStats(commodityId) {
  const [supplyRecords, consRecords] = await Promise.all([fetchSupplyRecords(), fetchConsumptionRecords()]);
  const supplyByCommodity = aggregateSupplyByCommodity(supplyRecords);
  const { byCommodity: consByCommodity, bySectorByCommodity } = aggregateConsumptionByCommodity(consRecords);

  const commodityName = commodityId && typeof commodityId === "string" ? commodityId.trim() : null;
  const commodities = Object.keys(supplyByCommodity);
  const resolvedCommodity = commodityName && commodities.includes(commodityName)
    ? commodityName
    : commodities[0];
  if (!resolvedCommodity) {
    throw new Error("No energy commodity data available.");
  }

  const analysis = buildCommodityAnalysis(supplyRecords, consRecords, resolvedCommodity);
  const forecast = buildCommodityForecast(analysis);
  const risk = getCommodityRisk(resolvedCommodity, analysis, forecast);
  const topSectors = getTopConsumingSectors(bySectorByCommodity, resolvedCommodity, 2);

  const supply = supplyByCommodity[resolvedCommodity] || {};
  const production = supply.production ?? 0;
  const imports = supply.imports ?? 0;
  const totalSupply = supply.supply ?? production + imports;
  const consumption = consByCommodity[resolvedCommodity] ?? 0;
  const importDependency = totalSupply > 0 ? (imports / totalSupply) * 100 : 0;
  const supplyGap = production - consumption;
  const ratio = analysis.latest?.ratio ?? null;
  const projectedDeficitYear = forecast?.projectedRatio != null && forecast.projectedRatio < 1 ? forecast.nextYear : null;

  const sectorImpact = topSectors.map((s) => `${s.name}: ${s.sharePct.toFixed(1)}%`).join("; ");

  return {
    commodity: resolvedCommodity,
    production,
    consumption,
    imports,
    stockChanges: supply.stockChanges ?? 0,
    totalSupply,
    supplyDemandRatio: ratio,
    importDependency,
    supplyGap,
    riskScore: risk.riskScore,
    riskReasons: risk.reasons,
    projectedDeficitYear,
    forecastStatus: forecast?.status ?? null,
    topSectors,
    sectorImpact,
    latestYear: analysis.latest?.fiscalYear ?? null,
    forecast,
    analysis,
  };
}

/** List all commodity names from live API. */
export async function listCommodities() {
  const supplyRecords = await fetchSupplyRecords();
  const byCommodity = aggregateSupplyByCommodity(supplyRecords);
  return Object.keys(byCommodity).sort();
}
