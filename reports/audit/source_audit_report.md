# Source Audit Report

**Generated:** 2026-03-11 11:09 UTC
**Total Sources Audited:** 18

## Executive Summary

- **Keep (High Quality):** 12 sources
- **Optimize (Medium Quality):** 3 sources
- **Remove (Low Quality):** 3 sources

## Detailed Source Analysis

| Source | Reliability | Discoveries | Ghosts | FP Rate | Unique | Recommendation |
|--------|-------------|-------------|--------|---------|--------|----------------|
| ZDI Advisories | 0.48 | 122 | 18.0% | 82.0% | 111 | **Keep** |
| Full Disclosure | 0.46 | 18 | 11.1% | 88.9% | 18 | **Keep** |
| Drupal Security Advisories | 0.40 | 8 | 0.0% | 100.0% | 8 | **Keep** |
| Palo Alto Networks Security Advisories | 0.40 | 22 | 0.0% | 100.0% | 22 | **Keep** |
| Splunk Security Advisories | 0.40 | 47 | 0.0% | 100.0% | 47 | **Keep** |
| Ubuntu Security Notices | 0.40 | 1 | 0.0% | 100.0% | 1 | **Remove** |
| Debian Security Tracker | 0.39 | 5403 | 0.6% | 99.4% | 5283 | **Keep** |
| Red Hat Security Data | 0.39 | 144 | 17.4% | 79.9% | 90 | **Keep** |
| CISA Known Exploited Vulnerabilities | 0.38 | 148 | 0.0% | 100.0% | 141 | **Keep** |
| Fortinet PSIRT | 0.38 | 19 | 0.0% | 100.0% | 18 | **Keep** |
| Cisco PSIRT | 0.37 | 62 | 0.0% | 100.0% | 57 | **Keep** |
| AWS Security Bulletins | 0.34 | 31 | 0.0% | 96.8% | 25 | **Keep** |
| GitHub Security Advisories | 0.32 | 256 | 0.4% | 99.6% | 188 | **Keep** |
| Canonical Ubuntu CVE Tracker | 0.29 | 3 | 0.0% | 100.0% | 2 | **Remove** |
| Project Zero Blog | 0.29 | 6 | 0.0% | 100.0% | 4 | **Optimize** |
| OSS Security | 0.27 | 44 | 9.1% | 90.9% | 18 | **Optimize** |
| Red Hat Security Advisories | 0.23 | 80 | 17.5% | 82.5% | 8 | **Optimize** |
| Chrome Releases | 0.14 | 32 | 3.1% | 96.9% | 3 | **Remove** |

## Recommendations

### Sources to Keep

- **ZDI Advisories**: Reliability 0.48, 122 discoveries
- **Full Disclosure**: Reliability 0.46, 18 discoveries
- **Drupal Security Advisories**: Reliability 0.40, 8 discoveries
- **Palo Alto Networks Security Advisories**: Reliability 0.40, 22 discoveries
- **Splunk Security Advisories**: Reliability 0.40, 47 discoveries
- **Debian Security Tracker**: Reliability 0.39, 5403 discoveries
- **Red Hat Security Data**: Reliability 0.39, 144 discoveries
- **CISA Known Exploited Vulnerabilities**: Reliability 0.38, 148 discoveries
- **Fortinet PSIRT**: Reliability 0.38, 19 discoveries
- **Cisco PSIRT**: Reliability 0.37, 62 discoveries
- **AWS Security Bulletins**: Reliability 0.34, 31 discoveries
- **GitHub Security Advisories**: Reliability 0.32, 256 discoveries

### Sources to Optimize

- **Project Zero Blog**: Reliability 0.29, FP rate 100.0%
- **OSS Security**: Reliability 0.27, FP rate 90.9%
- **Red Hat Security Advisories**: Reliability 0.23, FP rate 82.5%

### Sources to Remove

- **Ubuntu Security Notices**: Reliability 0.40 (few discoveries, low reliability)
- **Canonical Ubuntu CVE Tracker**: Reliability 0.29 (few discoveries, low reliability)
- **Chrome Releases**: Reliability 0.14 (low reliability)