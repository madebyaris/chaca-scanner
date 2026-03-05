import { create } from 'zustand';

export type ScanType = 'passive' | 'active' | 'full';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'firm' | 'tentative';
export type CmsType = 'wordpress' | 'drupal' | 'joomla' | 'shopify' | 'magento' | 'unknown';

export interface Vulnerability {
  id: string;
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
  references?: string[];
  cwe?: string;
}

export interface ApiExposure {
  endpoint: string;
  method: string;
  description: string;
  severity: Severity;
}

export interface DataExposure {
  field: string;
  data_type: string;
  location: string;
  severity: Severity;
  confidence: Confidence;
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
  timestamp?: number;
}

export interface ScanProgress {
  phase: string;
  current: number;
  total: number;
  message: string;
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

interface ScanState {
  url: string;
  scanType: ScanType;
  isScanning: boolean;
  progress: ScanProgress | null;
  result: ScanResult | null;
  error: string | null;
  view: View;
  history: ScanResult[];
  sidebarCollapsed: boolean;

  setUrl: (url: string) => void;
  setScanType: (type: ScanType) => void;
  startScan: () => void;
  setProgress: (progress: ScanProgress) => void;
  setResult: (result: ScanResult) => void;
  setError: (error: string) => void;
  setView: (view: View) => void;
  loadResult: (result: ScanResult) => void;
  clearHistory: () => void;
  toggleSidebar: () => void;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
  url: '',
  scanType: 'full',
  isScanning: false,
  progress: null,
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
    result: null,
    error: null,
    view: 'scanning',
  }),
  setProgress: (progress) => set({ progress }),
  setResult: (result) => set((state) => ({
    isScanning: false,
    progress: null,
    result: { ...result, timestamp: Date.now() },
    view: 'dashboard',
    history: [...state.history, { ...result, timestamp: Date.now() }].slice(-50),
  })),
  setError: (error) => set({
    isScanning: false,
    progress: null,
    error,
    view: 'new-scan',
  }),
  setView: (view) => set({ view }),
  loadResult: (result) => set({ result, view: 'dashboard' }),
  clearHistory: () => set({ history: [] }),
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  reset: () => set({
    url: '',
    scanType: 'full',
    isScanning: false,
    progress: null,
    result: null,
    error: null,
    view: 'new-scan',
  }),
}));
