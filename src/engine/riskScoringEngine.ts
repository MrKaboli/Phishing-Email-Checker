import {
  AIAnalysisOutput,
  AnalysisMode,
  AuthMechanismResult,
  CategorySummary,
  ExtractedUrlInfo,
  ParsedEmail,
  RuleCategory,
  RuleFinding,
  SeverityLevel,
  VerdictClassification,
} from '../types/phishguard';
import { INITIAL_CATEGORY_WEIGHTS, RISK_THRESHOLDS } from './config';

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(a: SeverityLevel, b: SeverityLevel): SeverityLevel {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

function computeCategoryScore(findings: RuleFinding[]): {
  score: number;
  highestSeverity: SeverityLevel;
} {
  if (findings.length === 0) {
    return { score: 0, highestSeverity: 'info' };
  }

  let highestSeverity: SeverityLevel = 'info';
  let rawSum = 0;

  for (const f of findings) {
    highestSeverity = maxSeverity(highestSeverity, f.severity);
    rawSum += f.scoreImpact;
  }

  // Diminishing-returns curve scaled to 0-100, with severity floors
  let normalized = Math.round(100 * (1 - Math.exp(-rawSum / 45)));

  if (highestSeverity === 'critical') {
    normalized = Math.max(normalized, 92);
  } else if (highestSeverity === 'high') {
    normalized = Math.max(normalized, 72);
  } else if (highestSeverity === 'medium') {
    normalized = Math.max(normalized, 42);
  } else if (highestSeverity === 'low') {
    normalized = Math.min(normalized, 35);
  }

  return {
    score: Math.min(100, Math.max(0, normalized)),
    highestSeverity,
  };
}

export function classifyRiskScore(score: number): VerdictClassification {
  if (score <= RISK_THRESHOLDS.SAFE_MAX) return 'safe';
  if (score <= RISK_THRESHOLDS.SUSPICIOUS_MAX) return 'suspicious';
  return 'likely_phishing';
}

export function calculateConfidence(
  email: ParsedEmail,
  authResults: { spf: AuthMechanismResult; dkim: AuthMechanismResult; dmarc: AuthMechanismResult },
  aiAvailable: boolean,
  aiConfidence?: number
): { confidence: number; factors: string[] } {
  let score = 55; // Base confidence
  const factors: string[] = [];

  if (email.rawHeadersPresent) {
    score += 15;
    factors.push('Full email headers provided (+15% technical visibility)');
  } else {
    score -= 10;
    factors.push('Full MIME headers were not provided (-10% header & routing visibility)');
  }

  const hasAuth =
    authResults.spf.result !== 'unavailable' ||
    authResults.dkim.result !== 'unavailable' ||
    authResults.dmarc.result !== 'unavailable';

  if (hasAuth) {
    score += 12;
    factors.push('Authentication-Results (SPF/DKIM/DMARC) available for inspection (+12%)');
  } else {
    score -= 6;
    factors.push('No SPF/DKIM/DMARC authentication headers available (-6%)');
  }

  const bodyLen = (email.textBody || '').length;
  if (bodyLen >= 120) {
    score += 8;
    factors.push('Sufficient email body content for linguistic and URL inspection (+8%)');
  } else if (bodyLen > 0 && bodyLen < 40) {
    score -= 10;
    factors.push('Very short email body limits linguistic pattern context (-10%)');
  }

  if (aiAvailable && typeof aiConfidence === 'number') {
    score += 10;
    // Blend deterministic evidence completeness (75%) with AI reported confidence (25%)
    score = Math.round(score * 0.75 + aiConfidence * 0.25);
    factors.push('Combined deterministic rule engine with Gemma 4 contextual analysis (+10%)');
  } else {
    factors.push('Calculated from deterministic rule-engine evidence only (AI analysis disabled or unavailable)');
  }

  return {
    confidence: Math.min(98, Math.max(25, Math.round(score))),
    factors,
  };
}

export function computeCombinedRiskAssessment(params: {
  email: ParsedEmail;
  extractedUrls: ExtractedUrlInfo[];
  findings: RuleFinding[];
  authResults: { spf: AuthMechanismResult; dkim: AuthMechanismResult; dmarc: AuthMechanismResult };
  aiOutput: AIAnalysisOutput | null;
}): {
  riskScore: number;
  classification: VerdictClassification;
  confidence: number;
  confidenceFactors: string[];
  analysisMode: AnalysisMode;
  categories: CategorySummary[];
  recommendations: string[];
  limitations: string[];
} {
  const { email, extractedUrls, findings, authResults, aiOutput } = params;
  const aiAvailable = aiOutput !== null;
  const analysisMode: AnalysisMode = aiAvailable ? 'full_ai_and_rules' : 'rule_only';

  // Group findings by category
  const byCategory: Record<Exclude<RuleCategory, 'ai_contextual'>, RuleFinding[]> = {
    url_security: findings.filter((f) => f.category === 'url_security'),
    sender_identity: findings.filter((f) => f.category === 'sender_identity'),
    authentication: findings.filter((f) => f.category === 'authentication'),
    social_engineering: findings.filter((f) => f.category === 'social_engineering'),
    attachment_security: findings.filter((f) => f.category === 'attachment_security'),
  };

  const urlStats = computeCategoryScore(byCategory.url_security);
  const senderStats = computeCategoryScore(byCategory.sender_identity);
  const authStats = computeCategoryScore(byCategory.authentication);
  const socialStats = computeCategoryScore(byCategory.social_engineering);
  const attachStats = computeCategoryScore(byCategory.attachment_security);

  // Renormalize weights if AI is unavailable
  const ruleWeightTotal =
    INITIAL_CATEGORY_WEIGHTS.url_security +
    INITIAL_CATEGORY_WEIGHTS.sender_identity +
    INITIAL_CATEGORY_WEIGHTS.authentication +
    INITIAL_CATEGORY_WEIGHTS.social_engineering +
    INITIAL_CATEGORY_WEIGHTS.attachment_security; // 0.90

  const normFactor = aiAvailable ? 1.0 : 1.0 / ruleWeightTotal;

  const effectiveWeights: Record<RuleCategory, number> = {
    url_security: Math.round(INITIAL_CATEGORY_WEIGHTS.url_security * normFactor * 100),
    sender_identity: Math.round(INITIAL_CATEGORY_WEIGHTS.sender_identity * normFactor * 100),
    authentication: Math.round(INITIAL_CATEGORY_WEIGHTS.authentication * normFactor * 100),
    social_engineering: Math.round(INITIAL_CATEGORY_WEIGHTS.social_engineering * normFactor * 100),
    attachment_security: Math.round(INITIAL_CATEGORY_WEIGHTS.attachment_security * normFactor * 100),
    ai_contextual: aiAvailable ? Math.round(INITIAL_CATEGORY_WEIGHTS.ai_contextual * 100) : 0,
  };

  // Compute Weighted Base Score from Rule Categories
  const ruleWeightedSum =
    urlStats.score * (INITIAL_CATEGORY_WEIGHTS.url_security / ruleWeightTotal) +
    senderStats.score * (INITIAL_CATEGORY_WEIGHTS.sender_identity / ruleWeightTotal) +
    authStats.score * (INITIAL_CATEGORY_WEIGHTS.authentication / ruleWeightTotal) +
    socialStats.score * (INITIAL_CATEGORY_WEIGHTS.social_engineering / ruleWeightTotal) +
    attachStats.score * (INITIAL_CATEGORY_WEIGHTS.attachment_security / ruleWeightTotal);

  // Evaluate Severity Distribution for Rule Escalation & Anti-Dilution Floors
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highFindings = findings.filter((f) => f.severity === 'high');
  const mediumFindings = findings.filter((f) => f.severity === 'medium');
  const onlyWeakFindings = criticalCount === 0 && highFindings.length === 0 && mediumFindings.length === 0;

  // Check specific confirmed high-risk technical vectors
  const hasConfirmedLookalikeUrl = extractedUrls.some(
    (u) => u.lookalikeBrand?.matchType === 'confirmed_lookalike'
  );
  const hasDisplayMismatch = extractedUrls.some((u) => Boolean(u.displayMismatch));
  const hasIpUrl = extractedUrls.some((u) => u.isIpAddress);
  const hasGiftCardScam = findings.some((f) => f.id === 'se-gift-card');
  const hasPromptInjection = findings.some((f) => f.id === 'se-prompt-injection');
  const hasCredHarvest = findings.some((f) => f.id === 'se-cred-harvest');

  // Check if the ONLY finding is an SPF or DKIM fail/softfail with no other suspicious signals
  const nonAuthFindings = findings.filter((f) => f.category !== 'authentication');
  const onlyAuthFailure = nonAuthFindings.length === 0 && byCategory.authentication.length > 0;

  let ruleFinalScore = Math.round(ruleWeightedSum);

  if (criticalCount > 0) {
    // Confirmed critical indicator (e.g. .pdf.exe double extension or .exe attachment)
    ruleFinalScore = Math.max(ruleFinalScore, 78 + Math.min(20, (criticalCount - 1) * 10 + highFindings.length * 6));
  } else if (highFindings.length >= 2) {
    // Multiple high-severity indicators across vectors
    ruleFinalScore = Math.max(ruleFinalScore, 70 + Math.min(26, (highFindings.length - 2) * 8 + mediumFindings.length * 4));
  } else if (
    hasConfirmedLookalikeUrl ||
    hasDisplayMismatch ||
    hasIpUrl ||
    hasGiftCardScam ||
    hasPromptInjection
  ) {
    // Single confirmed high-confidence technical/scam indicator
    ruleFinalScore = Math.max(ruleFinalScore, 64 + Math.min(25, mediumFindings.length * 6));
  } else if (hasCredHarvest) {
    // Direct credential harvesting language
    ruleFinalScore = Math.max(
      ruleFinalScore,
      extractedUrls.length > 0 || mediumFindings.length > 0 ? 64 : 52
    );
  } else if (highFindings.length === 1 && !onlyAuthFailure) {
    ruleFinalScore = Math.max(ruleFinalScore, 55 + Math.min(25, mediumFindings.length * 7));
  } else if (mediumFindings.length >= 2 && !onlyAuthFailure) {
    ruleFinalScore = Math.max(ruleFinalScore, 45 + Math.min(25, (mediumFindings.length - 2) * 8));
  } else if (mediumFindings.length === 1) {
    ruleFinalScore = Math.max(ruleFinalScore, 32);
  }

  // Enforce rule: A failed SPF or DKIM check alone should increase concern (suspicious) but NOT automatically establish phishing
  if (onlyAuthFailure) {
    ruleFinalScore = Math.min(ruleFinalScore, 42);
    ruleFinalScore = Math.max(ruleFinalScore, 30);
  }

  // Enforce rule: Multiple weak (low/info) indicators must not automatically produce a critical verdict
  if (onlyWeakFindings) {
    ruleFinalScore = Math.min(ruleFinalScore, 28);
  }

  ruleFinalScore = Math.min(100, Math.max(0, ruleFinalScore));

  // Combine with AI Contextual Analysis if available
  let finalRiskScore = ruleFinalScore;
  if (aiAvailable && aiOutput) {
    const blended = Math.round(ruleFinalScore * 0.85 + aiOutput.risk_score * 0.15);
    // Rule: AI must not override strong technical evidence without justification
    if (criticalCount > 0 || highFindings.length > 0) {
      finalRiskScore = Math.max(ruleFinalScore - 3, blended, aiOutput.risk_score > ruleFinalScore ? blended : ruleFinalScore);
    } else if (onlyAuthFailure) {
      finalRiskScore = Math.min(50, blended);
    } else {
      finalRiskScore = blended;
    }
  }

  finalRiskScore = Math.min(100, Math.max(0, finalRiskScore));
  const classification = classifyRiskScore(finalRiskScore);

  const { confidence, factors: confidenceFactors } = calculateConfidence(
    email,
    authResults,
    aiAvailable,
    aiOutput?.confidence
  );

  // Build Category Breakdown Summaries
  const buildStatus = (sev: SeverityLevel, count: number): CategorySummary['status'] => {
    if (count === 0 || sev === 'info') return 'clean';
    if (sev === 'critical' || sev === 'high') return 'critical';
    if (sev === 'medium') return 'warning';
    return 'info';
  };

  const categories: CategorySummary[] = [
    {
      category: 'url_security',
      label: 'URL & Link Security',
      status: buildStatus(urlStats.highestSeverity, byCategory.url_security.length),
      severity: urlStats.highestSeverity,
      score: urlStats.score,
      weight: effectiveWeights.url_security,
      findingsCount: byCategory.url_security.length,
      summaryText:
        byCategory.url_security.length > 0
          ? `${byCategory.url_security.length} link security warning(s) detected across ${extractedUrls.length} extracted URL(s).`
          : extractedUrls.length > 0
            ? `${extractedUrls.length} URL(s) inspected with no lookalike, IP, or mismatch indicators.`
            : 'No URLs detected in the email body.',
      recommendedAction:
        byCategory.url_security.length > 0
          ? 'Do not click embedded links. Navigate to official domains independently.'
          : 'Always inspect full destination domains before clicking links.',
    },
    {
      category: 'sender_identity',
      label: 'Sender Identity & Routing',
      status: buildStatus(senderStats.highestSeverity, byCategory.sender_identity.length),
      severity: senderStats.highestSeverity,
      score: senderStats.score,
      weight: effectiveWeights.sender_identity,
      findingsCount: byCategory.sender_identity.length,
      summaryText:
        byCategory.sender_identity.length > 0
          ? `${byCategory.sender_identity.length} sender identity or Reply-To/Return-Path anomaly detected.`
          : email.from
            ? `Sender header (${email.fromDomain || email.from}) shows no obvious display-name or routing spoofing.`
            : 'Sender header was not provided.',
      recommendedAction:
        byCategory.sender_identity.length > 0
          ? 'Verify the sender through an independent communication channel before replying.'
          : 'Confirm that the sender address matches your expected contact.',
    },
    {
      category: 'authentication',
      label: 'SPF / DKIM / DMARC',
      status:
        authResults.spf.result === 'unavailable' &&
        authResults.dkim.result === 'unavailable' &&
        authResults.dmarc.result === 'unavailable'
          ? 'unavailable'
          : buildStatus(authStats.highestSeverity, byCategory.authentication.length),
      severity: authStats.highestSeverity,
      score: authStats.score,
      weight: effectiveWeights.authentication,
      findingsCount: byCategory.authentication.length,
      summaryText:
        authResults.spf.result === 'unavailable' &&
        authResults.dkim.result === 'unavailable' &&
        authResults.dmarc.result === 'unavailable'
          ? 'Authentication-Results headers unavailable. Missing headers do not imply phishing.'
          : byCategory.authentication.length > 0
            ? `${byCategory.authentication.length} email authentication issue(s) reported in headers.`
            : 'Supplied Authentication-Results headers indicate passing checks.',
      recommendedAction:
        byCategory.authentication.length > 0
          ? 'Treat unauthenticated or failed-authentication messages with heightened caution.'
          : 'Include full raw MIME headers whenever possible for complete authentication analysis.',
    },
    {
      category: 'social_engineering',
      label: 'Social Engineering & Language',
      status: buildStatus(socialStats.highestSeverity, byCategory.social_engineering.length),
      severity: socialStats.highestSeverity,
      score: socialStats.score,
      weight: effectiveWeights.social_engineering,
      findingsCount: byCategory.social_engineering.length,
      summaryText:
        byCategory.social_engineering.length > 0
          ? `${byCategory.social_engineering.length} psychological manipulation, urgency, or lure pattern(s) detected.`
          : 'No coercive urgency, credential harvesting, or gift-card scam phrases matched.',
      recommendedAction:
        byCategory.social_engineering.length > 0
          ? 'Never comply with urgent requests for credentials, wire transfers, or gift cards.'
          : 'Remain alert to unexpected requests for sensitive actions.',
    },
    {
      category: 'attachment_security',
      label: 'Attachment Security',
      status: buildStatus(attachStats.highestSeverity, byCategory.attachment_security.length),
      severity: attachStats.highestSeverity,
      score: attachStats.score,
      weight: effectiveWeights.attachment_security,
      findingsCount: byCategory.attachment_security.length,
      summaryText:
        byCategory.attachment_security.length > 0
          ? `${byCategory.attachment_security.length} risky attachment indicator(s) across ${email.attachments.length} attachment(s).`
          : email.attachments.length > 0
            ? `${email.attachments.length} attachment filename(s) inspected with no high-risk extensions.`
            : 'No attachments present in the analyzed message.',
      recommendedAction:
        byCategory.attachment_security.length > 0
          ? 'Do not open, execute, or extract flagged attachments.'
          : 'Scan any unexpected attachments with endpoint antivirus before opening.',
    },
    {
      category: 'ai_contextual',
      label: 'Gemma 4 Contextual Analysis',
      status: !aiAvailable
        ? 'unavailable'
        : aiOutput.classification === 'likely_phishing'
          ? 'critical'
          : aiOutput.classification === 'suspicious'
            ? 'warning'
            : 'clean',
      severity: !aiAvailable
        ? 'info'
        : aiOutput.classification === 'likely_phishing'
          ? 'high'
          : aiOutput.classification === 'suspicious'
            ? 'medium'
            : 'info',
      score: aiAvailable ? aiOutput.risk_score : 0,
      weight: effectiveWeights.ai_contextual,
      findingsCount: aiAvailable
        ? aiOutput.social_engineering_tactics.length +
          aiOutput.impersonation_indicators.length +
          aiOutput.contextual_red_flags.length
        : 0,
      summaryText: aiAvailable
        ? aiOutput.summary
        : 'AI contextual analysis was disabled or unavailable; assessment relies 100% on deterministic security rules.',
      recommendedAction:
        aiAvailable && aiOutput.recommendations.length > 0
          ? aiOutput.recommendations[0]
          : 'Review the deterministic rule evidence and verify the sender independently.',
    },
  ];

  // Contextual Recommended Actions (Section 8.E)
  const recommendations: string[] = [];
  if (classification === 'likely_phishing') {
    recommendations.push(
      'Do not click any links or copy URLs from this email into your browser.',
      'Do not download, open, or execute any attached files.',
      'Do not reply to the sender or call phone numbers listed inside the message.',
      'Never provide passwords, MFA codes, banking details, or gift card codes.',
      'Report this email to your organization’s Security Operations / IT Helpdesk channel.',
      'Delete or quarantine the message after reporting.',
      'If the message claims to be from a vendor or institution, verify the request using an independently obtained contact number.'
    );
  } else if (classification === 'suspicious') {
    recommendations.push(
      'Verify the sender’s identity independently via a known phone number or trusted directory.',
      'Inspect the full message headers and link destinations carefully before taking action.',
      'Do not enter login credentials or sensitive financial information until the sender is verified.',
      'Navigate to any referenced account portal directly via a bookmark rather than clicking email links.'
    );
  } else {
    recommendations.push(
      'No obvious technical phishing indicators were detected in the supplied content.',
      'Still verify any unexpected financial, invoice, or account-related requests through an independent official channel.',
      'Remember that a low risk score does not guarantee sender legitimacy.'
    );
  }

  // Merge unique AI recommendations if available
  if (aiOutput?.recommendations) {
    for (const rec of aiOutput.recommendations) {
      if (rec && !recommendations.some((r) => r.toLowerCase() === rec.toLowerCase())) {
        recommendations.push(rec);
      }
    }
  }

  // Limitations disclosure
  const limitations: string[] = [
    'PhishGuard AI does not visit live URLs, resolve external DNS records, or detonate attachments in a sandbox.',
    'Authentication-Results headers are evaluated as supplied evidence and are not cryptographically re-verified against live DNS.',
  ];
  if (!email.rawHeadersPresent) {
    limitations.push('Full raw MIME headers were not provided, so Return-Path and SPF/DKIM/DMARC alignment could not be inspected.');
  }
  if (!aiAvailable) {
    limitations.push('Gemma 4 AI contextual analysis was not used for this scan; scoring is based strictly on the local deterministic rule engine.');
  }
  if (email.attachments.some((a) => /\.(zip|rar|7z|tar|gz)$/i.test(a.filename))) {
    limitations.push('Compressed archive attachment filenames were noted, but internal archive contents were not extracted or inspected.');
  }
  if (aiOutput?.limitations) {
    for (const lim of aiOutput.limitations) {
      if (lim && !limitations.includes(lim)) {
        limitations.push(lim);
      }
    }
  }

  return {
    riskScore: finalRiskScore,
    classification,
    confidence,
    confidenceFactors,
    analysisMode,
    categories,
    recommendations,
    limitations,
  };
}
