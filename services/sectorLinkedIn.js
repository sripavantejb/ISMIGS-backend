/**
 * Sector-specific LinkedIn post: filter by sector/commodity, real data only.
 */

import { fetchCommodityStats, listCommodities } from "./energyData.js";

function extractHashtags(text) {
  const tags = [];
  const re = /#[\w]+/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[0]);
  return tags;
}

function slugify(s) {
  return String(s).toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
}

/**
 * Resolve sector_key or sector_name to a commodity name for energy data.
 * e.g. "energy:coal" -> "Coal", "Electricity" -> "Electricity"
 */
function commodityFromSector(sectorKeyOrName) {
  if (!sectorKeyOrName || typeof sectorKeyOrName !== "string") return null;
  const s = sectorKeyOrName.trim();
  const idx = s.indexOf(":");
  if (idx > 0) {
    const type = s.slice(0, idx).toLowerCase();
    const slug = s.slice(idx + 1).trim();
    if (type === "energy" && slug) {
      const commodities = ["Coal", "Natural gas", "Crude oil", "Electricity", "Lignite", "Nuclear"];
      const lower = slug.toLowerCase();
      const found = commodities.find((c) => slugify(c) === lower);
      if (found) return found;
      return slug.charAt(0).toUpperCase() + slug.slice(1);
    }
  }
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * Generate sector-specific LinkedIn post: only that commodity and that sector's consumption share.
 * @param {{ sector_key?: string; sector_name: string }} sector - sector_key (e.g. energy:coal) and display name
 * @returns {Promise<{ post_content: string; hashtags: string[]; commodity: string; production: number; consumption: number; import_dependency: number; risk_score: number; projected_deficit_year: number | null; sector_impact: string }>}
 */
export async function generateSectorLinkedInPost(sector) {
  const sectorName = sector.sector_name || sector.sector_key || "Sector";
  const commodity = commodityFromSector(sector.sector_key || sectorName);
  const commodities = await listCommodities();
  const resolvedCommodity = commodity && commodities.includes(commodity) ? commodity : commodities[0];
  if (!resolvedCommodity) throw new Error("No energy commodity data available.");

  const stats = await fetchCommodityStats(resolvedCommodity);
  const {
    commodity: commName,
    production,
    consumption,
    importDependency,
    riskScore,
    riskReasons,
    projectedDeficitYear,
    forecastStatus,
    sectorImpact,
    topSectors,
  } = stats;

  const openaiKey = (process.env.OPENAI_API_KEY || process.env.OPEN_AI_API_KEY_ADMIN || "").trim();
  if (!openaiKey) throw new Error("OPENAI_API_KEY or OPEN_AI_API_KEY_ADMIN required.");

  const sectorRelevant = topSectors.filter(
    (s) => s.name && sectorName && s.name.toLowerCase().includes(sectorName.toLowerCase())
  );
  const sectorShare =
    sectorRelevant.length > 0
      ? sectorRelevant.map((s) => `${s.name}: ${s.sharePct.toFixed(1)}%`).join("; ")
      : sectorImpact || (topSectors.length ? topSectors.map((s) => `${s.name}: ${s.sharePct.toFixed(1)}%`).join("; ") : "");

  const dataBlurb = [
    `Commodity: ${commName}`,
    `Sector focus: ${sectorName}`,
    `Production: ${Math.round(production).toLocaleString()}`,
    `Consumption: ${Math.round(consumption).toLocaleString()}`,
    `Import dependency: ${importDependency.toFixed(2)}%`,
    `Risk score: ${riskScore}${riskReasons.length ? ` (${riskReasons.join("; ")})` : ""}`,
    projectedDeficitYear ? `Projected deficit year: ${projectedDeficitYear}` : "",
    forecastStatus ? `Forecast status: ${forecastStatus}` : "",
    sectorShare ? `Sector consumption share: ${sectorShare}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const systemPrompt = `You are a macro intelligence writer for ISMIGS (India State Macro Intelligence). Write a single LinkedIn post for policymakers and analysts using ONLY the data provided. Focus on the sector and commodity given. Format:
- One short headline (first line).
- Current production vs consumption (one line with numbers).
- Import dependency % (one line).
- Risk score and brief risk reason if any.
- One line forecast warning if projected deficit year is given.
- Sector impact: only the sector consumption share provided (do not add other sectors).
- One short strategic insight (1-2 sentences).
- End with 5-8 relevant hashtags. Use only the numbers and facts provided. Maximum 200 words. Professional tone.`;

  const body = {
    model: "gpt-3.5-turbo",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: `Data:\n${dataBlurb}` },
    ],
    max_tokens: 400,
    temperature: 0.4,
  };
  const fallbackKey = (process.env.OPEN_AI_API_KEY_ADMIN || "").trim();
  let res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${openaiKey}` },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && fallbackKey && fallbackKey !== openaiKey) {
    res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${fallbackKey}` },
      body: JSON.stringify(body),
    });
  }
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenAI API error: ${res.status} ${errText.slice(0, 200)}`);
  }
  const data = await res.json();
  const rawText = data.choices?.[0]?.message?.content?.trim();
  if (!rawText) throw new Error("OpenAI returned no content");

  const hashtags = extractHashtags(rawText);
  const post_content = rawText;

  return {
    post_content,
    hashtags,
    commodity: commName,
    production: Math.round(production),
    consumption: Math.round(consumption),
    import_dependency: Number(importDependency.toFixed(2)),
    risk_score: riskScore,
    projected_deficit_year: projectedDeficitYear ?? null,
    sector_impact: sectorShare || sectorImpact || "",
  };
}
