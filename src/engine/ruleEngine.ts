import {
  AIAnalysisOutput,
  AnalysisResult,
  AuthMechanismResult,
  EmailScanInput,
  ExtractedUrlInfo,
  ParsedEmail,
  RuleFinding,
} from '../types/phishguard';
import { analyzeAttachments } from './attachmentEngine';
import { parseEmailInput, validateEmailInput } from './emailParser';
import { prepareRedactedPayload, RedactedEmailPayload } from './redactionEngine';
import { computeCombinedRiskAssessment } from './riskScoringEngine';
import { analyzeSenderAndAuth } from './senderEngine';
import { analyzeSocialEngineering } from './socialEngine';
import { analyzeUrls } from './urlEngine';

export interface DeterministicRuleBundle {
  parsedEmail: ParsedEmail;
  extractedUrls: ExtractedUrlInfo[];
  findings: RuleFinding[];
  authResults: {
    spf: AuthMechanismResult;
    dkim: AuthMechanismResult;
    dmarc: AuthMechanismResult;
    rawHeader: string;
  };
  redactedPayload: RedactedEmailPayload;
}

export function runDeterministicRuleEngine(input: EmailScanInput): DeterministicRuleBundle {
  const validation = validateEmailInput(input);
  if (!validation.valid) {
    throw new Error(validation.error || 'Invalid email scan input.');
  }

  const parsedEmail = parseEmailInput(input);
  const { extractedUrls, findings: urlFindings } = analyzeUrls(parsedEmail);
  const { senderFindings, authFindings, authResults } = analyzeSenderAndAuth(parsedEmail);
  const socialFindings = analyzeSocialEngineering(parsedEmail);
  const attachmentFindings = analyzeAttachments(parsedEmail);

  const findings: RuleFinding[] = [
    ...urlFindings,
    ...senderFindings,
    ...authFindings,
    ...socialFindings,
    ...attachmentFindings,
  ];

  const redactedPayload = prepareRedactedPayload(parsedEmail, Boolean(input.redactPii));

  return {
    parsedEmail,
    extractedUrls,
    findings,
    authResults,
    redactedPayload,
  };
}

export function buildFinalAnalysisResult(params: {
  bundle: DeterministicRuleBundle;
  aiOutput: AIAnalysisOutput | null;
  aiModelUsed: string | null;
  aiStatusMessage?: string;
}): AnalysisResult {
  const { bundle, aiOutput, aiModelUsed, aiStatusMessage } = params;
  const { parsedEmail, extractedUrls, findings, authResults, redactedPayload } = bundle;

  const combined = computeCombinedRiskAssessment({
    email: parsedEmail,
    extractedUrls,
    findings,
    authResults,
    aiOutput,
  });

  const scanId = `pg-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

  return {
    scanId,
    timestamp: new Date().toISOString(),
    riskScore: combined.riskScore,
    classification: combined.classification,
    confidence: combined.confidence,
    confidenceFactors: combined.confidenceFactors,
    analysisMode: combined.analysisMode,
    aiModelUsed: combined.analysisMode === 'full_ai_and_rules' ? aiModelUsed : null,
    aiStatusMessage,
    redaction: redactedPayload.report,
    emailMetadata: {
      from: parsedEmail.from,
      fromDomain: parsedEmail.fromDomain,
      to: parsedEmail.to,
      replyTo: parsedEmail.replyTo,
      replyToDomain: parsedEmail.replyToDomain,
      returnPath: parsedEmail.returnPath,
      returnPathDomain: parsedEmail.returnPathDomain,
      subject: parsedEmail.subject || '(No Subject)',
      date: parsedEmail.date,
      messageId: parsedEmail.messageId,
      hasRawHeaders: parsedEmail.rawHeadersPresent,
      bodyLength: parsedEmail.textBody.length,
      attachmentCount: parsedEmail.attachments.length,
      urlCount: extractedUrls.length,
      parseWarnings: parsedEmail.parseWarnings,
    },
    authResults,
    extractedUrls,
    findings,
    categories: combined.categories,
    aiAnalysis: aiOutput,
    recommendations: combined.recommendations,
    limitations: combined.limitations,
  };
}
