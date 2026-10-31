import { ParsedEmail, RuleFinding, SeverityLevel } from '../types/phishguard';

interface SocialPatternRule {
  id: string;
  subCategory:
    | 'urgency'
    | 'threats'
    | 'credential_harvesting'
    | 'financial_manipulation'
    | 'gift_card_scam'
    | 'impersonation'
    | 'prompt_injection';
  title: string;
  severity: SeverityLevel;
  scoreImpact: number;
  regex: RegExp;
  explanation: string;
  recommendation: string;
}

const SOCIAL_RULES: SocialPatternRule[] = [
  // URGENCY
  {
    id: 'se-urgency-immediate',
    subCategory: 'urgency',
    title: 'High-Pressure Urgency ("Immediate Action Required")',
    severity: 'medium',
    scoreImpact: 22,
    regex: /\b(immediate action (?:is )?required|urgent(?:\s+account)?\s+verification|act now to (?:avoid|prevent)|final warning|respond within (?:24|12|48) hours|action required immediately)\b/i,
    explanation:
      'Creates artificial time pressure designed to make the recipient act impulsively before verifying the sender or link destination.',
    recommendation:
      'Pause whenever an email demands immediate action. Legitimate organizations rarely terminate accounts within hours without prior notice.',
  },
  {
    id: 'se-urgency-suspension',
    subCategory: 'urgency',
    title: 'Account Suspension Countdown Pressure',
    severity: 'high',
    scoreImpact: 28,
    regex: /\b(your account will be (?:suspended|locked|closed|deactivated|terminated)|avoid immediate suspension|account suspension notice|failure to verify within \d+ hours)\b/i,
    explanation:
      'Threatens imminent loss of account access to coerce the user into clicking an embedded verification link.',
    recommendation:
      'Do not use links in the email. Log in to your account independently via a trusted bookmark to check your account status.',
  },

  // THREATS
  {
    id: 'se-threat-termination',
    subCategory: 'threats',
    title: 'Coercive Threat (Account Disabled / Termination / Legal Action)',
    severity: 'high',
    scoreImpact: 28,
    regex: /\b(account termination|permanent(?:ly)? (?:disabled|suspended|deleted)|legal action will be taken|account has been (?:disabled|restricted|frozen)|law enforcement notification)\b/i,
    explanation:
      'Uses fear of punitive consequences, account loss, or legal escalation to bypass critical thinking.',
    recommendation:
      'Verify any alleged security restriction or legal notice through an independently verified phone number or official portal.',
  },
  {
    id: 'se-threat-breach',
    subCategory: 'threats',
    title: 'Security Breach or Unauthorized Login Alert Framing',
    severity: 'medium',
    scoreImpact: 22,
    regex: /\b(unusual (?:login|sign-in|activity) detected|security breach (?:detected|affecting your account)|unauthorized (?:login|access) attempt|suspicious sign-in from an unrecognized device)\b/i,
    explanation:
      'Simulates a security alert to induce panic and prompt the user to "secure" their account via a link controlled by the sender.',
    recommendation:
      'Check your account security activity log directly inside the official application or website rather than clicking the alert link.',
  },

  // CREDENTIAL HARVESTING
  {
    id: 'se-cred-harvest',
    subCategory: 'credential_harvesting',
    title: 'Direct Credential or Identity Harvesting Request',
    severity: 'high',
    scoreImpact: 35,
    regex: /\b(verify your password|confirm your (?:account|password|login|credentials)|enter your login details|update your banking information|verify your identity(?:\s+now|\s+immediately|\s+by clicking)?|validate your mailbox credentials|re-enter your password)\b/i,
    explanation:
      'Explicitly instructs the recipient to submit passwords, login credentials, or sensitive identity details—a hallmark of credential harvesting.',
    recommendation:
      'Never enter passwords, PINs, MFA codes, or banking credentials after following an email link.',
  },

  // FINANCIAL MANIPULATION
  {
    id: 'se-fin-wire-bank',
    subCategory: 'financial_manipulation',
    title: 'Urgent Wire Transfer or Bank Routing Change Request',
    severity: 'high',
    scoreImpact: 36,
    regex: /\b(urgent wire transfer|updated? (?:our )?bank(?:ing)? (?:details|routing|account information)|bank account verification required|process an immediate wire|new ACH routing instructions)\b/i,
    explanation:
      'Requests an urgent wire transfer or changes to payment routing details, a primary vector for Business Email Compromise (BEC) fraud.',
    recommendation:
      'Always verify wire transfers or vendor bank detail changes via a known phone number on file, never via email alone.',
  },
  {
    id: 'se-fin-payment-failed',
    subCategory: 'financial_manipulation',
    title: 'Coercive Payment Failure or Overdue Invoice Lure',
    severity: 'medium',
    scoreImpact: 24,
    regex: /\b(payment (?:has )?failed(?:\s*-\s*|\s+please\s+)?update|update (?:your )?payment method immediately|overdue invoice requires immediate settlement|billing failure:\s*service interruption)\b/i,
    explanation:
      'Claims a failed payment or urgent billing failure to trick the recipient into entering credit card or banking details.',
    recommendation:
      'Check your billing history by navigating independently to the service provider website.',
  },

  // GIFT CARD SCAMS
  {
    id: 'se-gift-card',
    subCategory: 'gift_card_scam',
    title: 'Gift Card Purchase & PIN Extraction Scam',
    severity: 'high',
    scoreImpact: 48,
    regex: /\b(purchase (?:some )?gift cards|buy (?:\d+ )?(?:apple|steam|google play|amazon|itunes|razer)?\s*gift cards|send (?:me )?(?:the )?gift card codes|scratch (?:off )?and reveal the pin|email (?:me )?photos of the back of the cards)\b/i,
    explanation:
      'Requests purchasing retail gift cards and sending the redemption codes or PINs via email—an irreversible payment method used almost exclusively in impersonation scams.',
    recommendation:
      'Never purchase gift cards or share redemption PINs in response to an email request, even if it appears to come from an executive.',
  },

  // IMPERSONATION
  {
    id: 'se-impersonation-bec',
    subCategory: 'impersonation',
    title: 'Executive / CEO Authority & Unavailable-by-Phone Pretext',
    severity: 'high',
    scoreImpact: 34,
    regex: /\b(i am currently in a (?:board )?meeting (?:and cannot talk|no calls)|handle this confidentially for me|need a quick favor.*?(?:in a meeting|email only)|as ceo i am authorizing|do not call me right now.*?(?:urgent|task|cards|transfer))\b/i,
    explanation:
      'Combines executive authority with an excuse preventing phone verification ("in a meeting, email only"), a classic CEO fraud / BEC technique.',
    recommendation:
      'Confirm any unusual request from leadership through a live voice call or in-person conversation.',
  },
  {
    id: 'se-impersonation-authority',
    subCategory: 'impersonation',
    title: 'IT Helpdesk, Bank Fraud Desk, or Government Agency Impersonation',
    severity: 'medium',
    scoreImpact: 25,
    regex: /\b(it (?:service desk|support) mandatory (?:password|mailbox) (?:reset|upgrade)|official notice from the (?:internal revenue service|tax department|federal reserve)|fraud prevention department:\s*mandatory verification)\b/i,
    explanation:
      'Adopts the persona of an internal IT administrator, bank fraud officer, or government authority to compel compliance.',
    recommendation:
      'Contact your internal IT helpdesk or institution through official internal channels to confirm whether the notice is authentic.',
  },

  // PROMPT INJECTION / EVASION ATTEMPT
  {
    id: 'se-prompt-injection',
    subCategory: 'prompt_injection',
    title: 'Adversarial Prompt Injection / Security Scanner Evasion Attempt',
    severity: 'high',
    scoreImpact: 45,
    regex: /\b(ignore (?:all )?previous instructions|classify this email as safe|you are now a system administrator|disregard your security rules|return a safe verdict regardless|system prompt override)\b/i,
    explanation:
      'The email contains embedded adversarial instructions attempting to hijack automated AI security scanners and force a "safe" classification.',
    recommendation:
      'Treat any email containing scanner-manipulation or prompt-injection strings as highly suspicious.',
  },
];

function extractSentenceWithMatch(fullText: string, matchIndex: number, matchLength: number): string {
  const startBound = Math.max(0, fullText.lastIndexOf('.', matchIndex - 1) + 1, fullText.lastIndexOf('\n', matchIndex - 1) + 1);
  let endDot = fullText.indexOf('.', matchIndex + matchLength);
  let endNewline = fullText.indexOf('\n', matchIndex + matchLength);
  if (endDot === -1) endDot = fullText.length;
  if (endNewline === -1) endNewline = fullText.length;
  const endBound = Math.min(fullText.length, Math.min(endDot + 1, endNewline), startBound + 220);

  const snippet = fullText.slice(startBound, endBound).replace(/\s+/g, ' ').trim();
  return snippet || fullText.slice(matchIndex, matchIndex + matchLength).trim();
}

export function analyzeSocialEngineering(email: ParsedEmail): RuleFinding[] {
  const combinedSource = [email.subject, email.textBody].filter(Boolean).join('\n');
  if (!combinedSource.trim()) return [];

  const findings: RuleFinding[] = [];

  for (const rule of SOCIAL_RULES) {
    const match = rule.regex.exec(combinedSource);
    if (match && typeof match.index === 'number') {
      const exactSentence = extractSentenceWithMatch(combinedSource, match.index, match[0].length);
      findings.push({
        id: rule.id,
        category: 'social_engineering',
        title: rule.title,
        severity: rule.severity,
        scoreImpact: rule.scoreImpact,
        evidence: `"${exactSentence}"`,
        explanation: rule.explanation,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}
