import { invoke } from '@tauri-apps/api/core';
import type { ScanResult, ScanType } from '@/store/scanStore';

export interface ScanRequest {
  url: string;
  scan_type: ScanType;
  config?: Record<string, unknown>;
}

export async function startScan(
  url: string,
  scanType: ScanType,
  config?: Record<string, unknown>,
): Promise<ScanResult> {
  const request: ScanRequest = {
    url,
    scan_type: scanType,
    ...(config && { config }),
  };
  
  return await invoke<ScanResult>('start_scan', { request });
}

export async function getAppInfo() {
  return await invoke<{ name: string; version: string; description: string }>('get_app_info');
}
