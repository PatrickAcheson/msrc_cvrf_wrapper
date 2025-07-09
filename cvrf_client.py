import datetime
import sys

import requests
import pandas as pd

API_VERSION = 'v3.0'
BASE_URL = f'https://api.msrc.microsoft.com/cvrf/{API_VERSION}/cvrf/'
HEADERS = {'Accept': 'application/json'}

THREAT_TYPE_VULN    = 0
THREAT_TYPE_EXPLOIT = 1

VULN_CLASSIFICATIONS = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium',
]


def current_year_month() -> str:
    return datetime.datetime.now().strftime("%Y-%b")

class MSRCStats:
    def __init__(self, year_month: str):
        self.year_month = year_month
        self.data = self._fetch_json()
        self.title = self.data.get('DocumentTitle', {}).get('Value', '[no title]')
        self.vulns = self.data.get('Vulnerability', [])

    def _fetch_json(self):
        url = BASE_URL + self.year_month
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code != 200:
            sys.exit(f"[!] HTTP {resp.status_code} – no data for {self.year_month}")
        return resp.json()

    def classification_counts(self):
        counts = {label: 0 for label in VULN_CLASSIFICATIONS}
        for v in self.vulns:
            seen = set()
            for t in v.get('Threats', []):
                if t.get('Type') != THREAT_TYPE_VULN:
                    continue
                desc = t.get('Description', {}).get('Value', '')
                if desc == 'Edge - Chromium':
                    if '11655' in t.get('ProductID', []):
                        seen.add('Edge - Chromium')
                elif desc in counts:
                    seen.add(desc)
            for label in seen:
                counts[label] += 1
        return pd.DataFrame.from_dict(counts, orient='index', columns=['Count']).rename_axis('Classification')

    def exploited_in_wild(self):
        rows = []
        for v in self.vulns:
            base = next((s.get('BaseScore', 0) for s in v.get('CVSSScoreSets', [])), 0)
            for t in v.get('Threats', []):
                if t.get('Type') == THREAT_TYPE_EXPLOIT and 'Exploited:Yes' in t.get('Description', {}).get('Value', ''):
                    rows.append({'CVE': v.get('CVE'), 'Score': base, 'Title': v.get('Title', {}).get('Value')})
                    break
        return pd.DataFrame(rows)

    def high_severity(self, threshold=8.0):
        rows = []
        for v in self.vulns:
            bs = next((float(s.get('BaseScore', 0)) for s in v.get('CVSSScoreSets', [])), 0.0)
            if bs >= threshold:
                rows.append({'CVE': v.get('CVE'), 'Score': bs, 'Title': v.get('Title', {}).get('Value')})
        return pd.DataFrame(rows)

    def likely_exploited(self):
        rows = []
        for v in self.vulns:
            for t in v.get('Threats', []):
                if t.get('Type') == THREAT_TYPE_EXPLOIT and 'exploitation more likely' in t.get('Description', {}).get('Value', '').lower():
                    rows.append({'CVE': v.get('CVE'), 'Title': v.get('Title', {}).get('Value')})
                    break
        return pd.DataFrame(rows)


def main():
    ym = current_year_month()
    stats = MSRCStats(ym)

    df_summary = pd.DataFrame({
        'Release Title': [stats.title],
        'Year-Month':     [stats.year_month],
        'Total Vulns':    [len(stats.vulns)]
    })
    df_class = stats.classification_counts()
    df_wild  = stats.exploited_in_wild()
    df_high  = stats.high_severity(threshold=8.0)
    df_likely= stats.likely_exploited()

    out_file = f"MSRC_{ym}.xlsx"
    with pd.ExcelWriter(out_file, engine='openpyxl') as writer:
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        df_class.to_excel(writer, sheet_name='By Classification')
        df_wild.to_excel(writer, sheet_name='Exploited in Wild', index=False)
        df_high.to_excel(writer, sheet_name='High Severity (≥8.0)', index=False)
        df_likely.to_excel(writer, sheet_name='Likely Exploited', index=False)

        for sheet in writer.sheets.values():
            for col_cells in sheet.columns:
                width = max(len(str(cell.value)) for cell in col_cells) + 2
                sheet.column_dimensions[col_cells[0].column_letter].width = width

    print(f"Wrote report to {out_file}")

if __name__ == '__main__':
    main()
