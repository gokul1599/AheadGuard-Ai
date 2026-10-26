import type {
  RiskOutcome,
  Finding,
  CheckPerformed,
  ModelInterpretation,
  ObservedFacts,
  ActionPreview,
  ObservedDestination,
  InvestigationReport,
} from "../../lib/types";

export type {
  RiskOutcome,
  Finding,
  CheckPerformed,
  ModelInterpretation,
  ObservedFacts,
  ActionPreview,
  ObservedDestination,
  InvestigationReport,
};

export interface ExtensionSettings {
  monitoringEnabled: boolean;
  historyPaused: boolean;
  backendUrl: string;
}

export interface ExtensionLedgerItem {
  investigationId: string;
  timestamp: string;
  url: string;
  host: string;
  riskOutcome: RiskOutcome;
  summary: string;
  proposedAction: string;
  finalUrl?: string;
}

export type ExtensionMessage =
  | { type: "GET_STATUS"; tabId?: number }
  | { type: "CHECK_URL"; url: string; tabId?: number }
  | { type: "GET_SETTINGS" }
  | { type: "UPDATE_SETTINGS"; settings: Partial<ExtensionSettings> }
  | { type: "CLEAR_LEDGER" }
  | { type: "GET_LEDGER" }
  | { type: "NAVIGATE_TAB"; tabId?: number; url: string };

export interface TabStatusResponse {
  tabId?: number;
  url?: string;
  isSupportedScheme: boolean;
  monitoringEnabled: boolean;
  historyPaused: boolean;
  activeReport?: InvestigationReport;
  lastCheckedUrl?: string;
  isChecking: boolean;
  error?: string;
}
