/**
 * Audit log: insert into audit_logs collection.
 * Used for create sector, create sector admin, approve/reject, etc.
 */

/**
 * @param {import("mongodb").Db} database
 * @param {{ user_id: string | import("mongodb").ObjectId; action: string; sector_id?: string | import("mongodb").ObjectId | null; meta?: object }} params
 */
export async function insertAuditLog(database, params) {
  if (!database) return;
  const { user_id, action, sector_id, meta } = params;
  await database.collection("audit_logs").insertOne({
    user_id: user_id ?? null,
    action: action || "unknown",
    sector_id: sector_id ?? null,
    timestamp: new Date(),
    meta: meta ?? null,
  });
}
