import type { ScanResult, Severity, Confidence } from '@/store/scanStore';

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
            version: '0.5.0',
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

export function exportByFormat(result: ScanResult, format: 'json' | 'csv' | 'sarif'): void {
  if (format === 'csv') {
    exportCSV(result);
    return;
  }
  if (format === 'sarif') {
    exportSARIF(result);
    return;
  }
  exportJSON(result);
}
