import { create } from 'zustand';
import { LazyStore } from '@tauri-apps/plugin-store';

export type ScanType = 'passive' | 'active' | 'full';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'firm' | 'tentative';
export type CmsType = 'wordpress' | 'drupal' | 'joomla' | 'shopify' | 'magento' | 'unknown';
export type DiscoveryMode = 'crawl' | 'artifact' | 'merged';

export interface EvidenceItem {
  kind: string;
  label: string;
  value: string;
}

export interface AuthState {
  mode: string;
  applied: boolean;
  status: string;
  details: string;
}

export interface InventorySummaryItem {
  url: string;
  method: string;
  source: string;
  tags: string[];
  parameter_names: string[];
  last_status?: number | null;
}

export interface ScanMetrics {
  request_count: number;
  endpoint_total: number;
  active_candidate_total: number;
  passive_vulnerability_count: number;
  active_vulnerability_count: number;
  api_exposure_count: number;
  data_exposure_count: number;
  artifact_seed_count: number;
  authenticated_request_count: number;
  confirmed_finding_count: number;
  tentative_finding_count: number;
}

export interface Vulnerability {
  id: string;
  rule_id?: string;
  fingerprint?: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  location: string;
  evidence: string;
  impact: string;
  remediation: string;
  affected_endpoints: string[];
  evidence_items?: EvidenceItem[];
  references?: string[];
  cwe?: string;
}

export interface ApiExposure {
  fingerprint?: string;
  endpoint: string;
  method: string;
  description: string;
  severity: Severity;
}

export interface DataExposure {
  fingerprint?: string;
  field: string;
  data_type: string;
  location: string;
  severity: Severity;
  confidence: Confidence;
  matched_value?: string;
}

export interface CookieInfo {
  name: string;
  domain: string;
  secure: boolean;
  http_only: boolean;
  same_site: string;
  path: string;
}

export interface HeaderPair {
  key: string;
  value: string;
}

export interface TargetInfo {
  ip_addresses: string[];
  server: string;
  powered_by: string;
  content_type: string;
  http_version: string;
  status_code: number;
  redirect_chain: string[];
  tls_issuer: string;
  tls_protocol: string;
  response_headers: HeaderPair[];
  cookies: CookieInfo[];
  technologies: string[];
  dns_records: string[];
  whois_org: string;
  cdn_provider: string;
  waf_detected: string;
  hosting_provider: string;
  framework: string;
  language: string;
  os_hint: string;
  open_ports_hint: string[];
  meta_generator: string;
  favicon_hash: string;
  robots_txt_exists: boolean;
  sitemap_exists: boolean;
  security_txt_exists: boolean;
  response_time_ms: number;
}

export interface ScanResult {
  url: string;
  scan_type: ScanType;
  vulnerabilities: Vulnerability[];
  api_exposures: ApiExposure[];
  data_exposures: DataExposure[];
  security_score: number;
  scan_duration_ms: number;
  cms_detected: CmsType | null;
  target_info?: TargetInfo | null;
  auth_state?: AuthState | null;
  inventory?: InventorySummaryItem[];
  metrics?: ScanMetrics | null;
  timestamp?: number;
}

export interface ScanProgress {
  phase: string;
  current: number;
  total: number;
  message: string;
  detail?: string;
  findings_so_far?: number;
}

export type View =
  | 'new-scan'
  | 'scanning'
  | 'dashboard'
  | 'report'
  | 'api-exposure'
  | 'data-exposure'
  | 'history'
  | 'settings'
  | 'about'
  | 'documentation';

export interface ActivityLogEntry {
  timestamp: number;
  phase: string;
  message: string;
  detail?: string;
}

const HISTORY_STORE_KEY = 'scan_history';
const historyStore = new LazyStore('history.json');

async function persistHistory(history: ScanResult[]): Promise<void> {
  try {
    await historyStore.set(HISTORY_STORE_KEY, history);
    await historyStore.save();
  } catch {
    // Silently fail in dev/browser context
  }
}

interface ScanState {
  url: string;
  scanType: ScanType;
  isScanning: boolean;
  progress: ScanProgress | null;
  activityLog: ActivityLogEntry[];
  scanStartedAt: number | null;
  result: ScanResult | null;
  error: string | null;
  view: View;
  history: ScanResult[];
  sidebarCollapsed: boolean;

  setUrl: (url: string) => void;
  setScanType: (type: ScanType) => void;
  startScan: () => void;
  setProgress: (progress: ScanProgress) => void;
  setResult: (result: ScanResult, historyLimit?: number) => void;
  setError: (error: string) => void;
  setView: (view: View) => void;
  loadResult: (result: ScanResult) => void;
  clearHistory: () => void;
  loadHistory: () => Promise<void>;
  toggleSidebar: () => void;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set, get) => ({
  url: '',
  scanType: 'full',
  isScanning: false,
  progress: null,
  activityLog: [],
  scanStartedAt: null,
  result: null,
  error: null,
  view: 'new-scan',
  history: [],
  sidebarCollapsed: false,

  setUrl: (url) => set({ url, error: null }),
  setScanType: (scanType) => set({ scanType }),
  startScan: () => set({
    isScanning: true,
    progress: { phase: 'initializing', current: 0, total: 100, message: 'Initializing scan...' },
    activityLog: [{ timestamp: Date.now(), phase: 'initializing', message: 'Scan started' }],
    scanStartedAt: Date.now(),
    result: null,
    error: null,
    view: 'scanning',
  }),
  setProgress: (progress) => set((state) => {
    const lastEntry = state.activityLog[state.activityLog.length - 1];
    const isDuplicate = lastEntry
      && lastEntry.phase === progress.phase
      && lastEntry.message === progress.message
      && lastEntry.detail === (progress.detail || undefined);

    const newLog = isDuplicate
      ? state.activityLog
      : [
          ...state.activityLog,
          {
            timestamp: Date.now(),
            phase: progress.phase,
            message: progress.message,
            detail: progress.detail || undefined,
          },
        ].slice(-200);

    return { progress, activityLog: newLog };
  }),
  setResult: (result, historyLimit = 50) => {
    const timestamp = Date.now();
    const stamped = { ...result, timestamp };
    set((state) => ({
      isScanning: false,
      progress: null,
      result: stamped,
      view: 'dashboard',
      history: [...state.history, stamped].slice(-historyLimit),
    }));
    persistHistory(get().history);
  },
  setError: (error) => set({
    isScanning: false,
    progress: null,
    error,
    view: 'new-scan',
  }),
  setView: (view) => set({ view }),
  loadResult: (result) => set({ result, view: 'dashboard' }),
  clearHistory: () => {
    set({ history: [] });
    persistHistory([]);
  },
  loadHistory: async () => {
    try {
      const saved = await historyStore.get<ScanResult[]>(HISTORY_STORE_KEY);
      if (saved && Array.isArray(saved)) {
        set({ history: saved });
      }
    } catch {
      // Silently fail in dev/browser context
    }
  },
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  reset: () => set({
    url: '',
    scanType: 'full',
    isScanning: false,
    progress: null,
    activityLog: [],
    scanStartedAt: null,
    result: null,
    error: null,
    view: 'new-scan',
  }),
}));
