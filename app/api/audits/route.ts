import { createAuditPostHandler } from "../../../lib/audits/audit-handler.ts";

// Next.js uses its Node.js runtime by default; cacheComponents disallows an explicit runtime export.
export const POST = createAuditPostHandler();