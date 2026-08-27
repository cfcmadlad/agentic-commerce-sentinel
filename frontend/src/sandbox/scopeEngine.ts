/**
 * Client-side port of Layer 2's transaction-scope rules.
 *
 * Mirrors `_check_transaction_scope` in `detect/scope.py` exactly: same six
 * rules, same exact comparisons, no tolerance band. This intentionally
 * covers only the transaction-scope half of Layer 2 (amount, currency,
 * category, merchant, time window) -- the three binding checks
 * (mandate/agent/user identity match) require a full session/mandate
 * identity model that doesn't fit a lightweight client-side sandbox, so
 * they're left out rather than faked.
 *
 * There is no backend behind this (Milestone E doesn't exist yet); this is
 * real logic re-implemented in TypeScript, not a simulation of an API call.
 * If Layer 2's actual rules ever change, this file needs the matching
 * edit by hand -- same maintenance contract `types/contract.ts` already
 * states for the backend types it mirrors.
 */

export interface SandboxMandate {
  maxAmount: number;
  currency: string;
  allowedMerchantCategories: string[];
  allowedItemCategories: string[];
  /** null means "any merchant within the allowed categories," matching MandateScope.allowed_merchant_ids. */
  allowedMerchantIds: string[] | null;
  /** Hours from a shared t=0, matching the mandate's own valid_from/valid_until window. */
  validFromHours: number;
  validUntilHours: number;
}

export interface SandboxTransaction {
  amount: number;
  currency: string;
  merchantCategory: string;
  itemCategory: string;
  merchantId: string;
  timestampHours: number;
}

export type ScopeViolation =
  | "amount_over_ceiling"
  | "currency_mismatch"
  | "merchant_category_not_allowed"
  | "item_category_not_allowed"
  | "merchant_not_allowed"
  | "outside_time_window";

export const VIOLATION_LABELS: Record<ScopeViolation, string> = {
  amount_over_ceiling: "amount over ceiling",
  currency_mismatch: "currency mismatch",
  merchant_category_not_allowed: "merchant category not allowed",
  item_category_not_allowed: "item category not allowed",
  merchant_not_allowed: "merchant not allowed",
  outside_time_window: "outside time window",
};

/**
 * Evaluates a transaction against a mandate's scope, exactly as Layer 2
 * does: every rule checked, every failing reason collected -- not
 * short-circuited on the first hit.
 *
 * @param mandate - The authorized scope.
 * @param tx - The attempted transaction.
 * @returns Every scope rule the transaction violates, in the same order
 *   `detect/scope.py::_check_transaction_scope` checks them.
 */
export function evaluateScope(mandate: SandboxMandate, tx: SandboxTransaction): ScopeViolation[] {
  const reasons: ScopeViolation[] = [];
  if (tx.amount > mandate.maxAmount) reasons.push("amount_over_ceiling");
  if (tx.currency !== mandate.currency) reasons.push("currency_mismatch");
  if (!mandate.allowedMerchantCategories.includes(tx.merchantCategory)) reasons.push("merchant_category_not_allowed");
  if (!mandate.allowedItemCategories.includes(tx.itemCategory)) reasons.push("item_category_not_allowed");
  if (mandate.allowedMerchantIds !== null && !mandate.allowedMerchantIds.includes(tx.merchantId)) {
    reasons.push("merchant_not_allowed");
  }
  if (!(mandate.validFromHours <= tx.timestampHours && tx.timestampHours <= mandate.validUntilHours)) {
    reasons.push("outside_time_window");
  }
  return reasons;
}
