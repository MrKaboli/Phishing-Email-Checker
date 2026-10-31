export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type VerdictClassification = 'safe' | 'suspicious' | 'likely_phishing';

export type AnalysisMode = 'full_ai_and_rules' | 'rule_only';

export type RuleCategory =
  | 'url_security'
  | 'sender_identity'
  | 'authentication'
  | 'social_engineering'
  | 'attachment_security'
  | 'ai_contextual';

export interface AttachmentMetadata {
  filename: string;
  contentType?: string;
  sizeBytes?: number;
}

export interface EmailScanInput {
  rawInput?: string;
  subject?: string;
  from?: string;
  to?: string;
  replyTo?: string;
  returnPath?: string;
  rawHeaders?: string;
  bodyText?: string;
  bodyHtml?: string;
  attachments?: AttachmentMetadata[];
  uploadedFileName?: string;
  uploadedFileSize?: number;
  enableAi?: boolean;
  redactPii?: boolean;
  preferredModel?: string;
}

export interface AnchorLinkPair {
  visibleText: string;
  href: string;
}

export interface ParsedEmail {
  from: string;
  fromName: string;
  fromAddress: string;
  fromDomain: string;
  to: string;
  replyTo: string;
  replyToDomain: string;
  returnPath: string;
  returnPathDomain: string;
  subject: string;
  date: string;
  messageId: string;
  authenticationResults: string;
  receivedHeaders: string[];
  rawHeadersPresent: boolean;
  headersMap: Record<string, string>;
  textBody: string;
  htmlBody: string;
  anchorLinks: AnchorLinkPair[];
  attachments: AttachmentMetadata[];
  parseWarnings: string[];
}

export interface ExtractedUrlInfo {
  originalUrl: string;
  defangedUrl: string;
  source: 'text' | 'html_href' | 'html_text';
  visibleText?: string;
  protocol: 'http' | 'https' | 'other';
  hostname: string;
  registrableDomain: string;
  tld: string;
  subdomainCount: number;
  isIpAddress: boolean;
  isShortener: boolean;
  isSuspiciousTld: boolean;
  isPunycode: boolean;
  hasExcessiveSubdomains: boolean;
  lookalikeBrand?: {
    targetBrand: string;
    officialDomain: string;
    matchType: 'confirmed_lookalike' | 'possible_lookalike';
    explanation: string;
  };
  obfuscationFlags: string[];
  displayMismatch?: {
    displayedText: string;
    actualDestinationDefanged: string;
    reason: string;
  };
  riskSeverity: SeverityLevel;
}

export interface AuthMechanismResult {
  mechanism: 'SPF' | 'DKIM' | 'DMARC';
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'unavailable';
  details: string;
  alignment?: string;
  explanation: string;
}

export interface RuleFinding {
  id: string;
  category: Exclude<RuleCategory, 'ai_contextual'>;
  title: string;
  severity: SeverityLevel;
  scoreImpact: number;
  evidence: string;
  explanation: string;
  recommendation: string;
}

export interface CategorySummary {
  category: RuleCategory;
  label: string;
  status: 'clean' | 'info' | 'warning' | 'critical' | 'unavailable';
  severity: SeverityLevel;
  score: number; // 0-100 normalized for this category
  weight: number; // effective weight percentage
  findingsCount: number;
  summaryText: string;
  recommendedAction: string;
}

export interface AISocialEngineeringTactic {
  tactic: string;
  evidence: string;
  explanation: string;
  severity: 'low' | 'medium' | 'high';
}

export interface AIAnalysisOutput {
  classification: VerdictClassification;
  confidence: number;
  risk_score: number;
  summary: string;
  social_engineering_tactics: AISocialEngineeringTactic[];
  impersonation_indicators: string[];
  contextual_red_flags: string[];
  credential_requests: string[];
  financial_requests: string[];
  recommendations: string[];
  limitations: string[];
}

export interface RedactionReport {
  enabled: boolean;
  emailsRedacted: number;
  phonesRedacted: number;
  namesRedacted: number;
  redactedSubject: string;
  redactedBodyPreview: string;
}

export interface AnalysisResult {
  scanId: string;
  timestamp: string;
  riskScore: number;
  classification: VerdictClassification;
  confidence: number;
  confidenceFactors: string[];
  analysisMode: AnalysisMode;
  aiModelUsed: string | null;
  aiStatusMessage?: string;
  redaction: RedactionReport;
  emailMetadata: {
    from: string;
    fromDomain: string;
    to: string;
    replyTo: string;
    replyToDomain: string;
    returnPath: string;
    returnPathDomain: string;
    subject: string;
    date: string;
    messageId: string;
    hasRawHeaders: boolean;
    bodyLength: number;
    attachmentCount: number;
    urlCount: number;
    parseWarnings: string[];
  };
  authResults: {
    spf: AuthMechanismResult;
    dkim: AuthMechanismResult;
    dmarc: AuthMechanismResult;
    rawHeader: string;
  };
  extractedUrls: ExtractedUrlInfo[];
  findings: RuleFinding[];
  categories: CategorySummary[];
  aiAnalysis: AIAnalysisOutput | null;
  recommendations: string[];
  limitations: string[];
}

export interface ScanHistoryEntry {
  scanId: string;
  timestamp: string;
  subject: string;
  senderDomain: string;
  senderDisplay: string;
  riskScore: number;
  classification: VerdictClassification;
  confidence: number;
  analysisMode: AnalysisMode;
  aiModelUsed: string | null;
  redactionEnabled: boolean;
  findingsSummary: {
    totalFindings: number;
    highOrCriticalCount: number;
    topTitles: string[];
  };
  fullResult: AnalysisResult;
}

export interface UserPreferences {
  aiAnalysisEnabled: boolean;
  redactPiiBeforeAi: boolean;
  preferredGemmaModel: 'gemma-4-31b-it' | 'gemma-4-26b-a4b-it';
  includeRawMetadataInExport: boolean;
}
