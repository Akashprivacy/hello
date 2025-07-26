
// This file defines types shared within the backend service.

export enum CookieCategory {
  NECESSARY = 'Necessary',
  ANALYTICS = 'Analytics',
  MARKETING = 'Marketing',
  FUNCTIONAL = 'Functional',
  UNKNOWN = 'Unknown',
}

export type ComplianceStatus = 'Compliant' | 'Pre-Consent Violation' | 'Post-Rejection Violation' | 'Unknown';
export type CookieParty = 'First' | 'Third';
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Unknown';

export interface CookieInfo {
  key: string;
  name: string;
  provider: string; 
  category: CookieCategory | string;
  expiry: string;
  purpose: string;
  party: CookieParty;
  isHttpOnly: boolean;
  isSecure: boolean;
  complianceStatus: ComplianceStatus;
}

export interface TrackerInfo {
    key: string;
    url: string;
    provider: string;
    category: CookieCategory | string;
    complianceStatus: ComplianceStatus;
}

export interface ComplianceInfo {
    riskLevel: RiskLevel;
    assessment: string;
}

export interface ScanResultData {
  cookies: CookieInfo[];
  trackers: TrackerInfo[];
  screenshotBase64: string;
  compliance: {
    gdpr: ComplianceInfo;
    ccpa: ComplianceInfo;
  };
}


// --- DPA Reviewer Types ---
export type DpaPerspective = 'controller' | 'processor';

export interface DpaClauseAnalysis {
  clause: string;
  summary: string;
  risk: string;
  riskLevel: RiskLevel;
  recommendation: string;
}

export interface DpaAnalysisResult {
  overallRisk: {
    level: RiskLevel;
    summary: string;
  };
  analysis: DpaClauseAnalysis[];
}

// --- Vulnerability Scanner Types ---
export type VulnerabilityRiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type VulnerabilityCategory = 'Security Headers' | 'Cookie Configuration' | 'Information Exposure' | 'Insecure Transport' | 'Software Fingerprinting' | 'Frontend Security' | 'Best Practices' | 'Unknown';

export interface VulnerabilityReference {
  title: string;
  url: string;
}

export interface VulnerabilityFinding {
  name: string;
  riskLevel: VulnerabilityRiskLevel;
  category: VulnerabilityCategory;
  description: string;
  impact: string;
  evidence: string;
  remediation: string;
  references: VulnerabilityReference[];
}

export interface VulnerabilityScanResult {
  overallRisk: {
    level: VulnerabilityRiskLevel;
    score: number; // 0-10 CVSS-like score
    summary: string;
  };
  findings: VulnerabilityFinding[];
}