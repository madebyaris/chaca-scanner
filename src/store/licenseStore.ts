import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';

export type LicenseTier = 'free' | 'pro';

export interface LicenseInfo {
  license_key: string;
  email: string;
  product_name: string;
  variant: string;
  valid: boolean;
  uses: number;
  created_at: string;
  verified_at: number;
}

export type ProFeature =
  | 'pdf-export'
  | 'scheduled-scans'
  | 'unlimited-history'
  | 'compliance-mapping'
  | 'attack-surface-graph'
  | 'authenticated-scanning'
  | 'scan-profiles'
  | 'scan-diff'
  | 'trending-analytics'
  | 'ai-remediation';

const PRO_FEATURES: Record<ProFeature, { label: string; description: string }> = {
  'pdf-export': {
    label: 'PDF Export',
    description: 'Export branded PDF reports with executive summaries',
  },
  'scheduled-scans': {
    label: 'Scheduled Scans',
    description: 'Set up recurring daily or weekly scans with drift detection',
  },
  'unlimited-history': {
    label: 'Unlimited History',
    description: 'Keep unlimited scan history with full trending data',
  },
  'compliance-mapping': {
    label: 'Compliance Mapping',
    description: 'Map findings to PCI DSS, SOC 2, HIPAA, and GDPR frameworks',
  },
  'attack-surface-graph': {
    label: 'Attack Surface Graph',
    description: 'Interactive visualization of your full attack surface',
  },
  'authenticated-scanning': {
    label: 'Authenticated Scanning',
    description: 'Scan behind login walls with session management',
  },
  'scan-profiles': {
    label: 'Scan Profiles',
    description: 'Save and reuse custom scan configurations',
  },
  'scan-diff': {
    label: 'Scan Diff',
    description: 'Visual side-by-side comparison between scan results',
  },
  'trending-analytics': {
    label: 'Trending Analytics',
    description: 'Track vulnerability trends and security score over time',
  },
  'ai-remediation': {
    label: 'AI Remediation',
    description: 'Context-specific fix suggestions powered by AI',
  },
};

interface LicenseState {
  tier: LicenseTier;
  license: LicenseInfo | null;
  isActivating: boolean;
  activationError: string | null;
  loaded: boolean;

  isPro: () => boolean;
  hasFeature: (feature: ProFeature) => boolean;
  getFeatureInfo: (feature: ProFeature) => { label: string; description: string };
  activate: (licenseKey: string) => Promise<void>;
  deactivate: () => Promise<void>;
  loadLicense: () => Promise<void>;
  revalidate: () => Promise<void>;
}

const STORE_KEY = 'license_info';
const lazyStore = new LazyStore('license.json');

const GUMROAD_PRODUCT_ID = 'chaca-pro';

export const useLicenseStore = create<LicenseState>((set, get) => ({
  tier: 'free',
  license: null,
  isActivating: false,
  activationError: null,
  loaded: false,

  isPro: () => get().tier === 'pro',

  hasFeature: (_feature: ProFeature) => {
    return get().tier === 'pro';
  },

  getFeatureInfo: (feature: ProFeature) => {
    return PRO_FEATURES[feature] ?? { label: feature, description: '' };
  },

  activate: async (licenseKey: string) => {
    set({ isActivating: true, activationError: null });
    try {
      const info = await invoke<LicenseInfo>('activate_license', {
        productId: GUMROAD_PRODUCT_ID,
        licenseKey,
      });
      await lazyStore.set(STORE_KEY, info);
      await lazyStore.save();
      set({ tier: 'pro', license: info, isActivating: false });
    } catch (err) {
      set({
        isActivating: false,
        activationError: typeof err === 'string' ? err : String(err),
      });
    }
  },

  deactivate: async () => {
    try {
      await invoke('deactivate_license');
    } catch {
      // Continue even if backend call fails
    }
    await lazyStore.delete(STORE_KEY);
    await lazyStore.save();
    set({ tier: 'free', license: null, activationError: null });
  },

  loadLicense: async () => {
    try {
      const saved = await lazyStore.get<LicenseInfo>(STORE_KEY);
      if (saved && saved.valid) {
        try {
          await invoke('restore_cached_license', { info: saved });
        } catch {
          // Rust side may reject expired cache — that's fine
        }
        set({ tier: 'pro', license: saved, loaded: true });
      } else {
        set({ loaded: true });
      }
    } catch {
      set({ loaded: true });
    }
  },

  revalidate: async () => {
    const { license } = get();
    if (!license) return;
    try {
      const info = await invoke<LicenseInfo>('activate_license', {
        productId: GUMROAD_PRODUCT_ID,
        licenseKey: license.license_key,
      });
      await lazyStore.set(STORE_KEY, info);
      await lazyStore.save();
      set({ tier: 'pro', license: info });
    } catch {
      set({ tier: 'free', license: null });
      await lazyStore.delete(STORE_KEY);
      await lazyStore.save();
    }
  },
}));

export { PRO_FEATURES };
