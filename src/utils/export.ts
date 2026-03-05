import type { ScanResult } from '@/store/scanStore';

export function exportJSON(result: ScanResult): void {
  const data = JSON.stringify(result, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `chaca-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function exportCSV(result: ScanResult): void {
  const rows: string[] = [];
  const headers = ['id', 'title', 'severity', 'confidence', 'category', 'location', 'description', 'evidence', 'impact', 'remediation', 'affected_endpoints'];

  rows.push(headers.join(','));

  for (const vuln of result.vulnerabilities) {
    rows.push(
      [
        escapeCSV(vuln.id),
        escapeCSV(vuln.title),
        escapeCSV(vuln.severity),
        escapeCSV(vuln.confidence ?? 'tentative'),
        escapeCSV(vuln.category),
        escapeCSV(vuln.location),
        escapeCSV(vuln.description),
        escapeCSV(vuln.evidence),
        escapeCSV(vuln.impact),
        escapeCSV(vuln.remediation),
        escapeCSV(String(vuln.affected_endpoints?.length ?? 0)),
      ].join(',')
    );
  }

  for (const exp of result.api_exposures) {
    rows.push(
      [
        escapeCSV(`api-${exp.endpoint}`),
        escapeCSV(`API Exposure: ${exp.endpoint}`),
        escapeCSV(exp.severity),
        escapeCSV('API Exposure'),
        escapeCSV(exp.endpoint),
        escapeCSV(exp.description),
        '',
        '',
        '',
      ].join(',')
    );
  }

  for (const exp of result.data_exposures) {
    rows.push(
      [
        escapeCSV(`data-${exp.field}`),
        escapeCSV(`Data Exposure: ${exp.data_type}`),
        escapeCSV(exp.severity),
        escapeCSV('Data Exposure'),
        escapeCSV(exp.location),
        escapeCSV(`Field: ${exp.field}`),
        '',
        '',
        '',
      ].join(',')
    );
  }

  const csv = rows.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `chaca-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
