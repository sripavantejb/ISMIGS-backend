/**
 * Generate LinkedIn post (real data only) for an energy commodity.
 */

import { fetchCommodityStats } from "./energyData.js";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

function extractHashtags(text) {
  const tags = [];
  const re = /#[\w]+/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[0]);
  return tags;
}

/**
 * Generate structured LinkedIn post from live commodity data.
 * Returns { linkedin_post_text, hashtags, stats_summary }.
 */
export async function generateLinkedInPost(commodityId) {
  const stats = await fetchCommodityStats(commodityId);
  const {
    commodity,
    production,
    consumption,
    imports,
    importDependency,
    supplyGap,
    riskScore,
    riskReasons,
    projectedDeficitYear,
    forecastStatus,
    sectorImpact,
    topSectors,
    supplyDemandRatio,
  } = stats;

  const statsSummary = {
    production: Math.round(production),
    consumption: Math.round(consumption),
    imports: Math.round(imports),
    import_dependency_pct: Number(importDependency.toFixed(2)),
    supply_gap: Math.round(supplyGap),
    supply_demand_ratio: supplyDemandRatio != null ? Number(supplyDemandRatio.toFixed(2)) : null,
    risk_score: riskScore,
    risk_reasons: riskReasons,
    projected_deficit_year: projectedDeficitYear,
    forecast_status: forecastStatus,
    top_sectors: topSectors.map((s) => ({ name: s.name, share_pct: s.sharePct })),
    sector_impact: sectorImpact,
  };

  if (!OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY required for LinkedIn post generation.");
  }

  const dataBlurb = [
    `Commodity: ${commodity}`,
    `Production: ${Math.round(production).toLocaleString()}`,
    `Consumption: ${Math.round(consumption).toLocaleString()}`,
    `Imports: ${Math.round(imports).toLocaleString()}`,
    `Import dependency: ${importDependency.toFixed(2)}%`,
    `Supply gap (production - consumption): ${Math.round(supplyGap).toLocaleString()}`,
    supplyDemandRatio != null ? `Supply/consumption ratio: ${supplyDemandRatio.toFixed(2)}` : "",
    `Risk score: ${riskScore}${riskReasons.length ? ` (${riskReasons.join("; ")})` : ""}`,
    projectedDeficitYear ? `Projected deficit year: ${projectedDeficitYear}` : "",
    forecastStatus ? `Forecast status: ${forecastStatus}` : "",
    sectorImpact ? `Top consuming sectors: ${sectorImpact}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const systemPrompt = `You are a macro intelligence writer for ISMIGS (India State Macro Intelligence). Write a single LinkedIn post for policymakers and analysts using ONLY the data provided. Format:
- One short headline (first line).
- Current production vs consumption (one line with numbers).
- Import dependency % (one line).
- Risk score and brief risk reason if any.
- One line forecast warning if projected deficit year is given.
- Sector impact summary (top 2 consuming sectors).
- One short strategic insight (1-2 sentences).
- End with 5-8 relevant hashtags based on the commodity (e.g. #ISMIGS #EnergySecurity #Coal #India). Use only the numbers and facts provided. Maximum 200 words. Professional tone.`;

  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Data:\n${dataBlurb}` },
      ],
      max_tokens: 400,
      temperature: 0.4,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenAI API error: ${res.status} ${errText.slice(0, 200)}`);
  }
  const data = await res.json();
  const rawText = data.choices?.[0]?.message?.content?.trim();
  if (!rawText) throw new Error("OpenAI returned no content");

  const hashtags = extractHashtags(rawText);
  const linkedin_post_text = rawText;

  return {
    linkedin_post_text,
    hashtags,
    stats_summary: statsSummary,
    commodity,
    production,
    consumption,
    import_dependency: importDependency,
    risk_score: riskScore,
    projected_deficit_year: projectedDeficitYear,
    sector_impact: sectorImpact,
  };
}
