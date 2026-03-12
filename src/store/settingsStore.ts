import { create } from 'zustand';
import { LazyStore } from '@tauri-apps/plugin-store';
import type { DiscoveryMode, Severity } from './scanStore';

export type SettingsTab = 'network' | 'crawling' | 'passive' | 'active' | 'owasp' | 'export' | 'presets' | 'license';

export interface HeaderPair {
  key: string;
  value: string;
}

export interface ScanSettings {
  // Network
  httpTimeoutSecs: number;
  acceptInvalidCerts: boolean;
  customUserAgent: string;
  customHeaders: HeaderPair[];
  rateLimitRps: number;

  // Crawling
  discoveryMode: DiscoveryMode;
  maxCrawlDepth: number;
  maxEndpoints: number;
  followRobotsTxt: boolean;
  scopeAllowlist: string[];
  scopeDenylist: string[];
  customApiPaths: string[];
  artifactInput: string;

  // Passive scan toggles
  passiveServerHeader: boolean;
  passiveXPoweredBy: boolean;
  passiveJsonApi: boolean;
  passiveHsts: boolean;
  passiveContentTypeOptions: boolean;
  passiveFrameOptions: boolean;
  passiveCsp: boolean;
  passiveCors: boolean;
  passiveReferrerPolicy: boolean;
  passivePermissionsPolicy: boolean;
  passiveCacheControl: boolean;
  passiveCookieFlags: boolean;
  passiveCsrf: boolean;
  passiveClickjack: boolean;
  passiveInfoDisclosure: boolean;
  passiveJwtAnalysis: boolean;
  passiveRatelimitCheck: boolean;
  passiveDeserCheck: boolean;
  cmsDetection: boolean;
  genericExposureChecks: boolean;
  checkExposedServices: boolean;
  checkAdminPanels: boolean;

  // Active scan toggles
  activeBola: boolean;
  activeSsrf: boolean;
  activeInjection: boolean;
  activeAuthBypass: boolean;
  activeOpenRedirect: boolean;
  activePathTraversal: boolean;
  activeCorsReflection: boolean;
  activeXssEnhanced: boolean;
  activeCsrfVerify: boolean;
  activeGraphql: boolean;
  activeResourceConsumption: boolean;
  bolaDiffThreshold: number;
  authBypassDiffThreshold: number;

  // Data detection
  entropyThreshold: number;
  maxPiiMatches: number;
  tier1Secrets: boolean;
  tier2Entropy: boolean;
  tier3Pii: boolean;
  minSeverity: Severity;

  // Scoring
  scoreCriticalWeight: number;
  scoreHighWeight: number;
  scoreMediumWeight: number;
  scoreLowWeight: number;
  scoreCriticalCap: number;
  scoreHighCap: number;
  scoreMediumCap: number;
  scoreLowCap: number;

  // Export
  defaultExportFormat: 'json' | 'csv' | 'sarif' | 'pdf';
  autoExportOnComplete: boolean;
  historyLimit: number;
}

const DEFAULT_CHROME_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36';

export const DEFAULT_SETTINGS: ScanSettings = {
  httpTimeoutSecs: 30,
  acceptInvalidCerts: true,
  customUserAgent: DEFAULT_CHROME_USER_AGENT,
  customHeaders: [],
  rateLimitRps: 0,

  discoveryMode: 'merged',
  maxCrawlDepth: 1,
  maxEndpoints: 100,
  followRobotsTxt: true,
  scopeAllowlist: [],
  scopeDenylist: [],
  customApiPaths: [],
  artifactInput: '',

  passiveServerHeader: true,
  passiveXPoweredBy: true,
  passiveJsonApi: true,
  passiveHsts: true,
  passiveContentTypeOptions: true,
  passiveFrameOptions: true,
  passiveCsp: true,
  passiveCors: true,
  passiveReferrerPolicy: true,
  passivePermissionsPolicy: true,
  passiveCacheControl: true,
  passiveCookieFlags: true,
  passiveCsrf: true,
  passiveClickjack: true,
  passiveInfoDisclosure: true,
  passiveJwtAnalysis: true,
  passiveRatelimitCheck: true,
  passiveDeserCheck: true,
  cmsDetection: true,
  genericExposureChecks: true,
  checkExposedServices: true,
  checkAdminPanels: true,

  activeBola: true,
  activeSsrf: true,
  activeInjection: true,
  activeAuthBypass: true,
  activeOpenRedirect: true,
  activePathTraversal: true,
  activeCorsReflection: true,
  activeXssEnhanced: true,
  activeCsrfVerify: true,
  activeGraphql: true,
  activeResourceConsumption: true,
  bolaDiffThreshold: 50,
  authBypassDiffThreshold: 100,

  entropyThreshold: 3.0,
  maxPiiMatches: 3,
  tier1Secrets: true,
  tier2Entropy: true,
  tier3Pii: true,
  minSeverity: 'info',

  scoreCriticalWeight: 15,
  scoreHighWeight: 10,
  scoreMediumWeight: 5,
  scoreLowWeight: 2,
  scoreCriticalCap: 30,
  scoreHighCap: 25,
  scoreMediumCap: 20,
  scoreLowCap: 10,

  defaultExportFormat: 'json',
  autoExportOnComplete: false,
  historyLimit: 50,
};

/** Convert frontend settings to the Rust ScanConfig shape */
export function toScanConfig(s: ScanSettings) {
  return {
    http_timeout_secs: s.httpTimeoutSecs,
    accept_invalid_certs: s.acceptInvalidCerts,
    custom_user_agent: s.customUserAgent,
    custom_headers: s.customHeaders.filter(h => h.key.trim() !== ''),
    rate_limit_rps: s.rateLimitRps,
    discovery_mode: s.discoveryMode,
    max_crawl_depth: s.maxCrawlDepth,
    max_endpoints: s.maxEndpoints,
    follow_robots_txt: s.followRobotsTxt,
    scope_allowlist: s.scopeAllowlist.filter(p => p.trim() !== ''),
    scope_denylist: s.scopeDenylist.filter(p => p.trim() !== ''),
    custom_api_paths: s.customApiPaths.filter(p => p.trim() !== ''),
    artifact_input: s.artifactInput,
    passive_server_header: s.passiveServerHeader,
    passive_x_powered_by: s.passiveXPoweredBy,
    passive_json_api: s.passiveJsonApi,
    passive_hsts: s.passiveHsts,
    passive_content_type_options: s.passiveContentTypeOptions,
    passive_frame_options: s.passiveFrameOptions,
    passive_csp: s.passiveCsp,
    passive_cors: s.passiveCors,
    passive_referrer_policy: s.passiveReferrerPolicy,
    passive_permissions_policy: s.passivePermissionsPolicy,
    passive_cache_control: s.passiveCacheControl,
    passive_cookie_flags: s.passiveCookieFlags,
    passive_csrf: s.passiveCsrf,
    passive_clickjack: s.passiveClickjack,
    passive_info_disclosure: s.passiveInfoDisclosure,
    passive_jwt_analysis: s.passiveJwtAnalysis,
    passive_ratelimit_check: s.passiveRatelimitCheck,
    passive_deser_check: s.passiveDeserCheck,
    cms_detection: s.cmsDetection,
    generic_exposure_checks: s.genericExposureChecks,
    check_exposed_services: s.checkExposedServices,
    check_admin_panels: s.checkAdminPanels,
    active_bola: s.activeBola,
    active_ssrf: s.activeSsrf,
    active_injection: s.activeInjection,
    active_auth_bypass: s.activeAuthBypass,
    active_open_redirect: s.activeOpenRedirect,
    active_path_traversal: s.activePathTraversal,
    active_cors_reflection: s.activeCorsReflection,
    active_xss_enhanced: s.activeXssEnhanced,
    active_csrf_verify: s.activeCsrfVerify,
    active_graphql: s.activeGraphql,
    active_resource_consumption: s.activeResourceConsumption,
    bola_diff_threshold: s.bolaDiffThreshold,
    auth_bypass_diff_threshold: s.authBypassDiffThreshold,
    entropy_threshold: s.entropyThreshold,
    max_pii_matches: s.maxPiiMatches,
    tier1_secrets: s.tier1Secrets,
    tier2_entropy: s.tier2Entropy,
    tier3_pii: s.tier3Pii,
    min_severity: s.minSeverity,
    score_critical_weight: s.scoreCriticalWeight,
    score_high_weight: s.scoreHighWeight,
    score_medium_weight: s.scoreMediumWeight,
    score_low_weight: s.scoreLowWeight,
    score_critical_cap: s.scoreCriticalCap,
    score_high_cap: s.scoreHighCap,
    score_medium_cap: s.scoreMediumCap,
    score_low_cap: s.scoreLowCap,
  };
}

const STORE_KEY = 'scan_settings';
const lazyStore = new LazyStore('settings.json');

interface SettingsState {
  settings: ScanSettings;
  activeTab: SettingsTab;
  loaded: boolean;

  setActiveTab: (tab: SettingsTab) => void;
  updateSettings: (partial: Partial<ScanSettings>) => void;
  resetSettings: () => void;
  loadSettings: () => Promise<void>;
  saveSettings: () => Promise<void>;
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  settings: { ...DEFAULT_SETTINGS },
  activeTab: 'network',
  loaded: false,

  setActiveTab: (tab) => set({ activeTab: tab }),

  updateSettings: (partial) => {
    set((state) => ({
      settings: { ...state.settings, ...partial },
    }));
    get().saveSettings();
  },

  resetSettings: () => {
    set({ settings: { ...DEFAULT_SETTINGS } });
    get().saveSettings();
  },

  loadSettings: async () => {
    try {
      const saved = await lazyStore.get<ScanSettings>(STORE_KEY);
      if (saved) {
        set({ settings: { ...DEFAULT_SETTINGS, ...saved }, loaded: true });
      } else {
        set({ loaded: true });
      }
    } catch {
      set({ loaded: true });
    }
  },

  saveSettings: async () => {
    try {
      await lazyStore.set(STORE_KEY, get().settings);
      await lazyStore.save();
    } catch {
      // Silently fail in dev/browser context
    }
  },
}));
