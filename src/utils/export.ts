import { jsPDF } from 'jspdf';
import type { ScanResult, Severity, Confidence } from '@/store/scanStore';

export type ExportFormat = 'json' | 'csv' | 'sarif' | 'pdf';

function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportJSON(result: ScanResult): void {
  const data = JSON.stringify(result, null, 2);
  downloadBlob(
    `chaca-${new Date().toISOString().split('T')[0]}.json`,
    new Blob([data], { type: 'application/json' })
  );
}

function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function exportCSV(result: ScanResult): void {
  const rows: string[] = [];
  const headers = ['id', 'fingerprint', 'title', 'severity', 'confidence', 'category', 'location', 'description', 'evidence', 'impact', 'remediation', 'affected_endpoints'];

  rows.push(headers.join(','));

  for (const vuln of result.vulnerabilities) {
    rows.push(
      [
        escapeCSV(vuln.id),
        escapeCSV(vuln.fingerprint ?? ''),
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
        escapeCSV(exp.fingerprint ?? ''),
        escapeCSV(`API Exposure: ${exp.endpoint}`),
        escapeCSV(exp.severity),
        escapeCSV('firm'),
        escapeCSV('API Exposure'),
        escapeCSV(exp.endpoint),
        escapeCSV(exp.description),
        '',
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
        escapeCSV(exp.fingerprint ?? ''),
        escapeCSV(`Data Exposure: ${exp.data_type}`),
        escapeCSV(exp.severity),
        escapeCSV(exp.confidence),
        escapeCSV('Data Exposure'),
        escapeCSV(exp.location),
        escapeCSV(`Field: ${exp.field}${exp.matched_value ? `; Match: ${exp.matched_value}` : ''}`),
        '',
        '',
        '',
        '',
      ].join(',')
    );
  }

  const csv = rows.join('\n');
  downloadBlob(
    `chaca-${new Date().toISOString().split('T')[0]}.csv`,
    new Blob([csv], { type: 'text/csv;charset=utf-8' })
  );
}

function severityLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function confidenceRank(confidence: Confidence): 'high' | 'medium' | 'low' {
  if (confidence === 'confirmed') return 'high';
  if (confidence === 'firm') return 'medium';
  return 'low';
}

export function exportSARIF(result: ScanResult): void {
  const apiRules = result.api_exposures.map((exp) => ({
    id: `api-exposure:${exp.endpoint}`,
    name: `API Exposure: ${exp.endpoint}`,
    shortDescription: { text: exp.description },
    fullDescription: { text: exp.description },
    help: { text: "Review why this endpoint is publicly reachable and whether it should require auth or be hidden from discovery." },
    properties: {
      tags: ['api-exposure'],
      precision: 'medium',
    },
  }))

  const dataRules = result.data_exposures.map((exp) => ({
    id: `data-exposure:${exp.field}:${exp.location}`,
    name: `Data Exposure: ${exp.data_type}`,
    shortDescription: { text: `${exp.field} exposed at ${exp.location}` },
    fullDescription: { text: `${exp.data_type} matched in a response body.` },
    help: { text: "Remove sensitive data from public responses or enforce field-level authorization." },
    properties: {
      tags: ['data-exposure', `confidence:${exp.confidence}`],
      precision: confidenceRank(exp.confidence),
    },
  }))

  const sarif = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Chaca',
            version: '0.6.0',
            informationUri: 'https://github.com/madebyaris',
            rules: [
              ...result.vulnerabilities.map((vuln) => ({
              id: vuln.rule_id ?? vuln.id,
              name: vuln.title,
              shortDescription: { text: vuln.title },
              fullDescription: { text: vuln.description },
              help: { text: vuln.remediation || vuln.impact },
              properties: {
                tags: [vuln.category, `confidence:${vuln.confidence}`],
                precision: confidenceRank(vuln.confidence),
              },
              })),
              ...apiRules,
              ...dataRules,
            ],
          },
        },
        results: [
          ...result.vulnerabilities.map((vuln) => ({
            ruleId: vuln.rule_id ?? vuln.id,
            level: severityLevel(vuln.severity),
            message: { text: `${vuln.title}: ${vuln.description}` },
            fingerprints: vuln.fingerprint
              ? { primaryLocationLineHash: vuln.fingerprint }
              : undefined,
            properties: {
              severity: vuln.severity,
              confidence: vuln.confidence,
              category: vuln.category,
              evidence: vuln.evidence,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: vuln.location || result.url,
                  },
                },
              },
            ],
          })),
          ...result.api_exposures.map((exp) => ({
            ruleId: `api-exposure:${exp.endpoint}`,
            level: severityLevel(exp.severity),
            message: { text: exp.description },
            fingerprints: exp.fingerprint
              ? { primaryLocationLineHash: exp.fingerprint }
              : undefined,
            properties: {
              severity: exp.severity,
              category: 'api-exposure',
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: exp.endpoint,
                  },
                },
              },
            ],
          })),
          ...result.data_exposures.map((exp) => ({
            ruleId: `data-exposure:${exp.field}:${exp.location}`,
            level: severityLevel(exp.severity),
            message: { text: `${exp.data_type}: ${exp.field} at ${exp.location}` },
            fingerprints: exp.fingerprint
              ? { primaryLocationLineHash: exp.fingerprint }
              : undefined,
            properties: {
              severity: exp.severity,
              confidence: exp.confidence,
              category: 'data-exposure',
              matched_value: exp.matched_value,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: exp.location,
                  },
                },
              },
            ],
          })),
        ],
      },
    ],
  };

  downloadBlob(
    `chaca-${new Date().toISOString().split('T')[0]}.sarif`,
    new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/sarif+json' })
  );
}

function redactForPdf(value: string | undefined): string {
  if (!value || value.trim() === '') return '';
  return '[REDACTED]';
}

export function exportPDF(result: ScanResult): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 20;
  let y = 20;
  const lineH = 6;

  const addText = (text: string, opts?: { fontSize?: number; bold?: boolean }) => {
    doc.setFontSize(opts?.fontSize ?? 10);
    doc.setFont('helvetica', opts?.bold ? 'bold' : 'normal');
    const lines = doc.splitTextToSize(text, pageW - 2 * margin);
    for (const line of lines) {
      if (y > 270) {
        doc.addPage();
        y = 20;
      }
      doc.text(line, margin, y);
      y += lineH;
    }
  };

  addText('Chaca Security Scan Report', { fontSize: 16, bold: true });
  y += 4;
  addText(`Target: ${result.url}`);
  addText(`Scan Type: ${result.scan_type.toUpperCase()} | Duration: ${result.scan_duration_ms}ms | Score: ${result.security_score}/100`);
  addText(`Generated: ${new Date().toISOString()}`);
  y += 8;

  addText('Summary', { fontSize: 12, bold: true });
  addText(`Vulnerabilities: ${result.vulnerabilities.length} | API Exposures: ${result.api_exposures.length} | Data Exposures: ${result.data_exposures.length}`);
  y += 8;

  if (result.vulnerabilities.length > 0) {
    addText('Vulnerabilities', { fontSize: 12, bold: true });
    for (const v of result.vulnerabilities.slice(0, 50)) {
      if (y > 265) {
        doc.addPage();
        y = 20;
      }
      addText(`[${v.severity.toUpperCase()}] ${v.title}`);
      addText(`  ${v.description.substring(0, 120)}${v.description.length > 120 ? '...' : ''}`);
      y += 2;
    }
    if (result.vulnerabilities.length > 50) {
      addText(`... and ${result.vulnerabilities.length - 50} more`);
    }
    y += 6;
  }

  if (result.api_exposures.length > 0) {
    addText('API Exposures', { fontSize: 12, bold: true });
    for (const e of result.api_exposures.slice(0, 30)) {
      if (y > 265) {
        doc.addPage();
        y = 20;
      }
      addText(`[${e.severity.toUpperCase()}] ${e.endpoint} - ${e.description.substring(0, 80)}`);
      y += 2;
    }
    if (result.api_exposures.length > 30) {
      addText(`... and ${result.api_exposures.length - 30} more`);
    }
    y += 6;
  }

  if (result.data_exposures.length > 0) {
    addText('Data Exposures (sensitive values redacted)', { fontSize: 12, bold: true });
    for (const e of result.data_exposures.slice(0, 30)) {
      if (y > 265) {
        doc.addPage();
        y = 20;
      }
      const matchDisplay = e.matched_value ? redactForPdf(e.matched_value) : 'N/A';
      addText(`[${e.severity.toUpperCase()}] ${e.field} (${e.data_type}) at ${e.location} - Match: ${matchDisplay}`);
      y += 2;
    }
    if (result.data_exposures.length > 30) {
      addText(`... and ${result.data_exposures.length - 30} more`);
    }
  }

  const filename = `chaca-${new Date().toISOString().split('T')[0]}.pdf`;
  doc.save(filename);
}

export function exportByFormat(result: ScanResult, format: ExportFormat): void {
  if (format === 'csv') {
    exportCSV(result);
    return;
  }
  if (format === 'sarif') {
    exportSARIF(result);
    return;
  }
  if (format === 'pdf') {
    exportPDF(result);
    return;
  }
  exportJSON(result);
}
