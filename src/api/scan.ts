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

export async function cancelScan() {
  return await invoke<void>('cancel_scan');
}

export async function activateLicense(productId: string, licenseKey: string) {
  return await invoke<unknown>('activate_license', { productId, licenseKey });
}

export async function deactivateLicense() {
  return await invoke<void>('deactivate_license');
}

export async function getLicenseStatus() {
  return await invoke<{ is_pro: boolean; license: unknown }>('get_license_status');
}
