import { create } from 'zustand';
import { LazyStore } from '@tauri-apps/plugin-store';
import type { ScanType } from './scanStore';
import type { ScanSettings } from './settingsStore';
import { DEFAULT_SETTINGS } from './settingsStore';
import { useSettingsStore } from './settingsStore';
import { useScanStore } from './scanStore';

export interface ScanPreset {
  id: string;
  name: string;
  description: string;
  scanType: ScanType;
  settingsSnapshot: ScanSettings;
  createdAt: number;
  updatedAt: number;
  isBuiltIn?: boolean;
}

const BUILTIN_PRESETS: ScanPreset[] = [
  {
    id: 'quick-passive',
    name: 'Quick passive',
    description: 'Fast headers and exposure checks',
    scanType: 'passive',
    settingsSnapshot: {
      ...DEFAULT_SETTINGS,
      maxCrawlDepth: 1,
      maxEndpoints: 50,
      activeBola: false,
      activeSsrf: false,
      activeInjection: false,
      activeAuthBypass: false,
      activeOpenRedirect: false,
      activePathTraversal: false,
      activeCorsReflection: false,
      activeXssEnhanced: false,
      activeCsrfVerify: false,
      activeGraphql: false,
      activeResourceConsumption: false,
    },
    createdAt: 0,
    updatedAt: 0,
    isBuiltIn: true,
  },
  {
    id: 'api-audit',
    name: 'API audit',
    description: 'API exposure and endpoint discovery',
    scanType: 'full',
    settingsSnapshot: {
      ...DEFAULT_SETTINGS,
      discoveryMode: 'merged',
      maxCrawlDepth: 2,
      maxEndpoints: 150,
      genericExposureChecks: true,
      checkExposedServices: true,
      checkAdminPanels: true,
    },
    createdAt: 0,
    updatedAt: 0,
    isBuiltIn: true,
  },
  {
    id: 'full-scan',
    name: 'Full scan',
    description: 'Comprehensive vulnerability audit',
    scanType: 'full',
    settingsSnapshot: { ...DEFAULT_SETTINGS },
    createdAt: 0,
    updatedAt: 0,
    isBuiltIn: true,
  },
];

const PRESETS_STORE_KEY = 'scan_presets';
const presetStore = new LazyStore('presets.json');

function generateId(): string {
  return `preset-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

interface PresetState {
  presets: ScanPreset[];
  loaded: boolean;

  loadPresets: () => Promise<void>;
  savePresets: (presets: ScanPreset[]) => Promise<void>;
  getPresets: () => ScanPreset[];
  getPreset: (id: string) => ScanPreset | undefined;
  applyPreset: (id: string) => void;
  createPreset: (name: string, description?: string) => void;
  updatePreset: (id: string, updates: Partial<Pick<ScanPreset, 'name' | 'description' | 'scanType' | 'settingsSnapshot'>>) => void;
  deletePreset: (id: string) => void;
}

export const usePresetStore = create<PresetState>((set, get) => ({
  presets: [],
  loaded: false,

  loadPresets: async () => {
    try {
      const saved = await presetStore.get<ScanPreset[]>(PRESETS_STORE_KEY);
      const custom = saved && Array.isArray(saved) ? saved : [];
      const builtIn = BUILTIN_PRESETS;
      set({ presets: [...builtIn, ...custom], loaded: true });
    } catch {
      set({ presets: [...BUILTIN_PRESETS], loaded: true });
    }
  },

  savePresets: async (presets: ScanPreset[]) => {
    try {
      const custom = presets.filter((p) => !p.isBuiltIn);
      await presetStore.set(PRESETS_STORE_KEY, custom);
      await presetStore.save();
    } catch {
      // Silently fail in dev/browser context
    }
  },

  getPresets: () => get().presets,

  getPreset: (id: string) => get().presets.find((p) => p.id === id),

  applyPreset: (id: string) => {
    const preset = get().presets.find((p) => p.id === id);
    if (!preset) return;
    useSettingsStore.getState().updateSettings(preset.settingsSnapshot);
    useScanStore.getState().setScanType(preset.scanType);
  },

  createPreset: (name: string, description?: string) => {
    const settings = useSettingsStore.getState().settings;
    const scanType = useScanStore.getState().scanType;
    const now = Date.now();
    const newPreset: ScanPreset = {
      id: generateId(),
      name,
      description: description ?? name,
      scanType,
      settingsSnapshot: { ...settings },
      createdAt: now,
      updatedAt: now,
    };
    set((state) => {
      const next = [...state.presets, newPreset];
      get().savePresets(next);
      return { presets: next };
    });
  },

  updatePreset: (id, updates) => {
    set((state) => {
      const next = state.presets.map((p) =>
        p.id === id ? { ...p, ...updates, updatedAt: Date.now() } : p
      );
      get().savePresets(next);
      return { presets: next };
    });
  },

  deletePreset: (id: string) => {
    const preset = get().presets.find((p) => p.id === id);
    if (preset?.isBuiltIn) return;
    set((state) => {
      const next = state.presets.filter((p) => p.id !== id);
      get().savePresets(next);
      return { presets: next };
    });
  },
}));

export { BUILTIN_PRESETS };
