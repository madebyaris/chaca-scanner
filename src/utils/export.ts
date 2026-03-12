import { jsPDF } from 'jspdf';
import type { ScanResult, Severity, Confidence } from '@/store/scanStore';
import { useSettingsStore } from '@/store/settingsStore';

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

function buildExportBasename(result: ScanResult): string {
  const host = result.url
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()

  return `chaca-${host || 'scan'}-${new Date().toISOString().split('T')[0]}`
}

function clampText(value: string, max = 140): string {
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

function hexToRgb(hex: string, fallback: [number, number, number]): [number, number, number] {
  const normalized = hex.trim();
  if (!/^#[0-9a-fA-F]{6}$/.test(normalized)) return fallback;
  return [
    parseInt(normalized.slice(1, 3), 16),
    parseInt(normalized.slice(3, 5), 16),
    parseInt(normalized.slice(5, 7), 16),
  ];
}

function bestTextColorFor(rgb: [number, number, number]): [number, number, number] {
  const luminance = (0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]) / 255;
  return luminance > 0.62 ? [25, 25, 25] : [255, 255, 255];
}

function safeJoin(values: string[], fallback = 'N/A'): string {
  const filtered = values.filter(Boolean);
  return filtered.length > 0 ? filtered.join(', ') : fallback;
}

export function exportPDF(result: ScanResult): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const settings = useSettingsStore.getState().settings;
  const brandName = settings.brandingCompanyName.trim() || 'Chaca';
  const brandTagline = settings.brandingCompanyTagline.trim() || 'Security Scan Report';
  const brandWebsite = settings.brandingCompanyWebsite.trim();
  const primaryContact = settings.brandingPrimaryContact.trim();
  const logo = settings.brandingLogoDataUrl;
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 16;
  let y = 18;

  const black: [number, number, number] = [25, 25, 25];
  const primary = hexToRgb(settings.brandingPrimaryColor, black);
  const accent = hexToRgb(settings.brandingAccentColor, [196, 164, 74]);
  const border = hexToRgb(settings.brandingBorderColor, [224, 213, 200]);
  const panelBg = hexToRgb(settings.brandingSectionBackground, [250, 247, 244]);
  const muted: [number, number, number] = [115, 115, 115];
  const primaryText = bestTextColorFor(primary);

  const ensureSpace = (height: number) => {
    if (y + height <= pageH - 14) return;
    doc.addPage();
    y = 18;
  };

  const write = (
    text: string,
    opts?: {
      x?: number;
      width?: number;
      size?: number;
      bold?: boolean;
      color?: [number, number, number];
      gap?: number;
    },
  ) => {
    doc.setFont('helvetica', opts?.bold ? 'bold' : 'normal');
    doc.setFontSize(opts?.size ?? 10);
    const color = opts?.color ?? black;
    doc.setTextColor(color[0], color[1], color[2]);
    const lines = doc.splitTextToSize(text, opts?.width ?? pageW - margin * 2);
    doc.text(lines, opts?.x ?? margin, y);
    y += lines.length * (opts?.gap ?? ((opts?.size ?? 10) * 0.52));
  };

  const sectionTitle = (title: string, subtitle?: string) => {
    ensureSpace(24);
    doc.setDrawColor(border[0], border[1], border[2]);
    doc.line(margin, y, pageW - margin, y);
    y += 6;
    write(title, { size: 13, bold: true });
    if (subtitle) {
      write(subtitle, { size: 9, color: muted, gap: 4.8 });
    }
    y += 2;
  };

  const metricCard = (x: number, width: number, label: string, value: string) => {
    const top = y;
    doc.setFillColor(panelBg[0], panelBg[1], panelBg[2]);
    doc.setDrawColor(border[0], border[1], border[2]);
    doc.roundedRect(x, top, width, 24, 2, 2, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(115, 115, 115);
    doc.text(label, x + 4, top + 7);
    doc.setFontSize(16);
    doc.setTextColor(25, 25, 25);
    doc.text(value, x + 4, top + 17);
  };

  const findingBlock = (title: string, severity: string, body: string, detail?: string) => {
    ensureSpace(30);
    const top = y;
    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(border[0], border[1], border[2]);
    doc.roundedRect(margin, top, pageW - margin * 2, 24, 2, 2, 'FD');
    doc.setFillColor(accent[0], accent[1], accent[2]);
    doc.rect(margin, top, 4, 24, 'F');
    y += 5;
    write(`[${severity.toUpperCase()}] ${title}`, { x: margin + 8, width: pageW - margin * 2 - 12, size: 10, bold: true, gap: 5.2 });
    write(body, { x: margin + 8, width: pageW - margin * 2 - 12, size: 9, color: muted, gap: 4.7 });
    if (detail) {
      write(detail, { x: margin + 8, width: pageW - margin * 2 - 12, size: 8, color: black, gap: 4.2 });
    }
    y = top + 28;
  };

  doc.setFillColor(primary[0], primary[1], primary[2]);
  doc.rect(0, 0, pageW, 36, 'F');
  doc.setFillColor(accent[0], accent[1], accent[2]);
  doc.rect(0, 36, pageW, 3, 'F');
  if (logo) {
    try {
      doc.addImage(logo, 'PNG', margin, 10, 30, 10);
    } catch {
      // Ignore invalid logo data and continue with text branding.
    }
  }
  doc.setTextColor(primaryText[0], primaryText[1], primaryText[2]);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text(brandName, margin + (logo ? 36 : 0), 16);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(brandTagline, margin + (logo ? 36 : 0), 23);

  y = 48;
  write('Executive Summary', { size: 17, bold: true });
  write(
    `Target ${result.url} was scanned in ${result.scan_duration_ms}ms using ${result.scan_type.toUpperCase()} mode. This report is formatted for stakeholder review while keeping sensitive values redacted.`,
    { size: 10, color: muted, gap: 5.2 },
  );

  ensureSpace(30);
  metricCard(margin, 42, 'SECURITY SCORE', `${result.security_score}/100`);
  metricCard(margin + 46, 42, 'VULNERABILITIES', String(result.vulnerabilities.length));
  metricCard(margin + 92, 42, 'API EXPOSURES', String(result.api_exposures.length));
  metricCard(margin + 138, 42, 'DATA EXPOSURES', String(result.data_exposures.length));
  y += 30;

  sectionTitle('Client Target Intelligence', 'Infrastructure and stack details captured during the scan to prove coverage and context.');
  if (result.target_info) {
    const intelligenceCards: Array<[string, string]> = [
      ['IP', safeJoin(result.target_info.ip_addresses)],
      ['Hosting', result.target_info.hosting_provider || 'Unknown'],
      ['Server', result.target_info.server || 'Unknown'],
      ['Framework', result.target_info.framework || 'Unknown'],
      ['Language', result.target_info.language || 'Unknown'],
      ['HTTP', result.target_info.http_version || 'Unknown'],
      ['Status', String(result.target_info.status_code || 'N/A')],
      ['Response', `${result.target_info.response_time_ms}ms`],
    ];

    for (let i = 0; i < intelligenceCards.length; i += 2) {
      ensureSpace(20);
      const top = y;
      const left = intelligenceCards[i];
      const right = intelligenceCards[i + 1];

      const infoCard = (x: number, item: [string, string]) => {
        doc.setFillColor(255, 255, 255);
        doc.setDrawColor(border[0], border[1], border[2]);
        doc.roundedRect(x, top, 86, 18, 2, 2, 'FD');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(muted[0], muted[1], muted[2]);
        doc.text(item[0], x + 4, top + 6);
        doc.setFontSize(11);
        doc.setTextColor(black[0], black[1], black[2]);
        const lines = doc.splitTextToSize(item[1], 76);
        doc.text(lines, x + 4, top + 13);
      };

      infoCard(margin, left);
      if (right) infoCard(margin + 90, right);
      y += 22;
    }

    write(`Detected technologies: ${safeJoin(result.target_info.technologies)}`, { size: 9, color: muted, gap: 4.8 });
    write(`CDN / WAF: ${result.target_info.cdn_provider || 'Unknown'} / ${result.target_info.waf_detected || 'Unknown'}`, { size: 9, color: muted, gap: 4.8 });
  } else {
    write('No target intelligence data was captured for this scan.', { size: 9, color: muted, gap: 4.8 });
  }

  sectionTitle('Scan Context');
  write(`Generated: ${new Date().toLocaleString()}`, { size: 9, color: muted, gap: 4.8 });
  write(`Scan mode: ${result.scan_type.toUpperCase()}`, { size: 9, color: muted, gap: 4.8 });
  write(`Auth status: ${(result.auth_state?.status ?? 'anonymous').toUpperCase()} (${result.auth_state?.mode ?? 'anonymous'})`, { size: 9, color: muted, gap: 4.8 });
  if (brandWebsite || primaryContact) {
    write(
      [brandWebsite && `Website: ${brandWebsite}`, primaryContact && `Contact: ${primaryContact}`]
        .filter(Boolean)
        .join('   •   '),
      { size: 9, color: muted, gap: 4.8 },
    );
  }

  sectionTitle('Top Findings', 'Highest-risk issues first with concise remediation context.');
  if (result.vulnerabilities.length === 0) {
    findingBlock('No vulnerabilities detected', 'info', 'No vulnerability records were included in this scan result.');
  } else {
    result.vulnerabilities.slice(0, 8).forEach((vuln) => {
      findingBlock(
        vuln.title,
        vuln.severity,
        clampText(vuln.description, 180),
        clampText(`Remediation: ${vuln.remediation}`, 180),
      );
    });
  }

  sectionTitle('Detailed Vulnerabilities', 'Expanded findings with evidence summaries.');
  if (result.vulnerabilities.length === 0) {
    write('No vulnerability findings to include.', { size: 9, color: muted });
  } else {
    result.vulnerabilities.forEach((vuln) => {
      findingBlock(
        vuln.title,
        vuln.severity,
        clampText(vuln.description, 220),
        clampText(`Location: ${vuln.location} • Confidence: ${vuln.confidence.toUpperCase()}`, 220),
      );
    });
  }

  if (result.api_exposures.length > 0) {
    sectionTitle('API Exposure Review', 'Endpoints that may warrant access control or discovery hardening.');
    result.api_exposures.forEach((exposure) => {
      findingBlock(
        `${exposure.method} ${exposure.endpoint}`,
        exposure.severity,
        clampText(exposure.description, 220),
      );
    });
  }

  if (result.data_exposures.length > 0) {
    sectionTitle('Data Exposure Review', 'Sensitive matches remain redacted in exported PDF output.');
    result.data_exposures.forEach((exposure) => {
      findingBlock(
        `${exposure.field} (${exposure.data_type})`,
        exposure.severity,
        clampText(`Location: ${exposure.location}`, 220),
        `Matched value: ${redactForPdf(exposure.matched_value) || 'N/A'}`,
      );
    });
  }

  const totalPages = doc.getNumberOfPages();
  for (let page = 1; page <= totalPages; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(border[0], border[1], border[2]);
    doc.line(margin, pageH - 12, pageW - margin, pageH - 12);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(muted[0], muted[1], muted[2]);
    doc.text(`${brandName} • ${brandTagline}`, margin, pageH - 7);
    doc.text(`Page ${page} of ${totalPages}`, pageW - margin - 20, pageH - 7);
  }

  doc.save(`${buildExportBasename(result)}.pdf`);
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
