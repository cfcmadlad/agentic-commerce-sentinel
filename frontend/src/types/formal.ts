/**
 * Types for `frontend/public/formal_properties.json`, produced by
 * `run_verify_policy_properties.py --json-out`. Each property's name,
 * layer, and description come straight from `formal/properties.py`; only
 * `proved`/`counterexample` are the actual Z3 run's own output.
 */

export interface FormalProperty {
  name: string;
  layer: string;
  description: string;
  proved: boolean;
  counterexample: Record<string, string> | null;
}

export interface FormalPropertiesReport {
  properties: FormalProperty[];
  all_proved: boolean;
}
