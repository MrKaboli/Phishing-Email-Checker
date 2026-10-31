import { AuthMechanismResult, ParsedEmail, RuleFinding } from '../types/phishguard';
import { FREE_EMAIL_PROVIDERS, LEGITIMATE_ESP_DOMAINS, PROTECTED_BRANDS } from './config';
import { detectLookalikeDomain, parseDomainComponents } from './urlEngine';

function getRegistrable(domain: string): string {
  if (!domain) return '';
  return parseDomainComponents(domain).registrableDomain;
}

function isKnownEspDomain(domain: string): boolean {
  const reg = getRegistrable(domain);
  return LEGITIMATE_ESP_DOMAINS.has(reg) || LEGITIMATE_ESP_DOMAINS.has(domain.toLowerCase());
}

function parseSingleAuthMechanism(
  authHeader: string,
  mechanism: 'SPF' | 'DKIM' | 'DMARC',
  rawHeadersPresent: boolean
): AuthMechanismResult {
  const mechLower = mechanism.toLowerCase();

  if (!authHeader) {
    return {
      mechanism,
      result: 'unavailable',
      details: rawHeadersPresent
        ? `No ${mechanism} entry found in Authentication-Results header`
        : 'Full email headers not provided',
      explanation: rawHeadersPresent
        ? `The provided headers did not contain a ${mechanism} verification entry. Missing authentication metadata is not proof of phishing, but reduces technical verification confidence.`
        : `${mechanism} status cannot be evaluated because full MIME headers were not included with the scan. Header authentication results are supplied evidence rather than independently verified DNS records.`,
    };
  }

  // Match e.g. spf=pass (google.com: domain of ...), dkim=fail, dmarc=softfail
  const regex = new RegExp(`\\b${mechLower}\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b([^;|]*)`, 'i');
  const match = authHeader.match(regex);

  if (!match) {
    return {
      mechanism,
      result: 'unavailable',
      details: `Not reported in Authentication-Results`,
      explanation: `An Authentication-Results header was present, but no explicit ${mechanism} result was recorded by the receiving mail server.`,
    };
  }

  const rawResult = match[1].toLowerCase() as AuthMechanismResult['result'];
  const extraContext = (match[2] || '').trim().replace(/^[:\s]+/, '');

  // Check alignment info if present
  const alignMatch = extraContext.match(/header\.(?:from|i|d)=([^\s;)]+)/i) || extraContext.match(/smtp\.mailfrom=([^\s;)]+)/i);
  const alignment = alignMatch ? alignMatch[0] : undefined;

  const explanations: Record<AuthMechanismResult['result'], string> = {
    pass: `${mechanism} reported "pass" in the supplied message header (${extraContext || 'verified by receiving MTA'}). Note: Header results are evidence supplied by the message headers, not independently verified DNS or cryptographic truth.`,
    fail: `${mechanism} reported an explicit "fail" in the Authentication-Results header. The sending server was not authorized or the cryptographic signature was invalid.`,
    softfail: `${mechanism} reported "softfail" (~all), indicating the sending IP is not explicitly authorized by the domain's policy, though not strictly rejected.`,
    neutral: `${mechanism} reported "neutral", meaning the domain owner makes no assertion about the sending host's authorization.`,
    none: `${mechanism} reported "none", indicating no policy record or signature was published for the sender domain.`,
    temperror: `${mechanism} encountered a temporary DNS or verification error ("temperror") during transit.`,
    permerror: `${mechanism} encountered a permanent configuration error ("permerror") in the domain's published records.`,
    unavailable: `${mechanism} result unavailable.`,
  };

  return {
    mechanism,
    result: rawResult,
    details: extraContext || `Reported ${rawResult}`,
    alignment,
    explanation: explanations[rawResult],
  };
}

export function analyzeSenderAndAuth(email: ParsedEmail): {
  senderFindings: RuleFinding[];
  authFindings: RuleFinding[];
  authResults: {
    spf: AuthMechanismResult;
    dkim: AuthMechanismResult;
    dmarc: AuthMechanismResult;
    rawHeader: string;
  };
} {
  const senderFindings: RuleFinding[] = [];
  const authFindings: RuleFinding[] = [];

  const fromReg = getRegistrable(email.fromDomain);
  const replyToReg = getRegistrable(email.replyToDomain);
  const returnPathReg = getRegistrable(email.returnPathDomain);

  // 1. Parse Authentication-Results first so sender checks can reference them
  const spf = parseSingleAuthMechanism(email.authenticationResults, 'SPF', email.rawHeadersPresent);
  const dkim = parseSingleAuthMechanism(email.authenticationResults, 'DKIM', email.rawHeadersPresent);
  const dmarc = parseSingleAuthMechanism(email.authenticationResults, 'DMARC', email.rawHeadersPresent);

  // 2. Check if From domain is a lookalike of a protected brand
  if (email.fromDomain) {
    const parsedFromDom = parseDomainComponents(email.fromDomain);
    const lookalike = detectLookalikeDomain(
      email.fromDomain,
      parsedFromDom.registrableDomain,
      parsedFromDom.domainLabel
    );
    if (lookalike) {
      senderFindings.push({
        id: 'sender-lookalike-domain',
        category: 'sender_identity',
        title: `Sender Domain Impersonates ${lookalike.targetBrand}`,
        severity: lookalike.matchType === 'confirmed_lookalike' ? 'high' : 'medium',
        scoreImpact: lookalike.matchType === 'confirmed_lookalike' ? 45 : 30,
        evidence: `From: ${email.from}`,
        explanation: lookalike.explanation,
        recommendation: `Do not trust the sender address. Contact ${lookalike.targetBrand} only via their official domain (${lookalike.officialDomain}).`,
      });
    }
  }

  // 3. Check Display Name Impersonation & Free Email Provider Impersonation
  if (email.fromName && email.fromDomain) {
    const lowerName = email.fromName.toLowerCase();
    const isFreeProvider = FREE_EMAIL_PROVIDERS.has(fromReg);

    // Check if Display Name contains a different email address (e.g. "admin@company.com <attacker@gmail.com>")
    const embeddedEmailMatch = email.fromName.match(/([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))/);
    if (embeddedEmailMatch) {
      const embeddedAddr = embeddedEmailMatch[1].toLowerCase();
      const embeddedDom = getRegistrable(embeddedEmailMatch[2]);
      if (embeddedDom && embeddedDom !== fromReg) {
        senderFindings.push({
          id: 'sender-display-embedded-email',
          category: 'sender_identity',
          title: 'Deceptive Email Address Embedded in Sender Display Name',
          severity: 'high',
          scoreImpact: 42,
          evidence: `Display Name: "${email.fromName}" vs. Actual Address: <${email.fromAddress}>`,
          explanation: `The sender display name includes the email address "${embeddedAddr}" to trick email clients that hide the bracketed address, while the message actually originates from "${email.fromAddress}".`,
          recommendation: 'Always expand the sender details in your mail client to verify the actual address inside angle brackets.',
        });
      }
    }

    // Check if Display Name claims a Protected Brand while using an unrelated or free email domain
    for (const brand of PROTECTED_BRANDS) {
      if (lowerName.includes(brand.keyword) || lowerName.includes(brand.name.toLowerCase())) {
        const isOfficial = brand.officialDomains.some(
          (d) => fromReg === d || email.fromDomain.toLowerCase().endsWith(`.${d}`)
        );
        if (!isOfficial) {
          senderFindings.push({
            id: 'sender-brand-impersonation',
            category: 'sender_identity',
            title: isFreeProvider
              ? `Free Email Provider (${fromReg}) Impersonating ${brand.name}`
              : `Display-Name Brand Impersonation (${brand.name})`,
            severity: 'high',
            scoreImpact: isFreeProvider ? 45 : 38,
            evidence: `From: "${email.fromName}" <${email.fromAddress}>`,
            explanation: isFreeProvider
              ? `The sender display name claims to be "${email.fromName}" (${brand.name}), but uses a consumer free webmail account (${email.fromAddress}). Official ${brand.name} communications do not originate from personal ${fromReg} accounts.`
              : `The sender display name references ${brand.name} ("${email.fromName}"), but the actual sending domain "${fromReg}" does not match ${brand.name}'s official domains (${brand.officialDomains.join(', ')}).`,
            recommendation: `Do not reply or follow instructions. Verify the message directly with ${brand.name}.`,
          });
          break;
        }
      }
    }

    // Check if Display Name claims an Executive / Corporate Role from a Free Email Provider
    const executiveRoleRegex = /\b(ceo|chief executive|cfo|president|managing director|hr department|it helpdesk|security team|payroll|accounts payable)\b/i;
    if (isFreeProvider && executiveRoleRegex.test(email.fromName) && !senderFindings.some((f) => f.id === 'sender-brand-impersonation')) {
      senderFindings.push({
        id: 'sender-free-exec-impersonation',
        category: 'sender_identity',
        title: 'Corporate or Executive Role Using Free Webmail Provider',
        severity: 'high',
        scoreImpact: 38,
        evidence: `From: "${email.fromName}" <${email.fromAddress}>`,
        explanation: `The sender display name claims an executive or internal organizational role ("${email.fromName}"), but is sent from a public consumer email service (${fromReg}). This is a classic Business Email Compromise (BEC) pattern.`,
        recommendation: 'Verify internal executive or department requests via an internal corporate directory or phone call.',
      });
    }
  }

  // 4. Compare From vs. Reply-To domain
  if (fromReg && replyToReg && fromReg !== replyToReg) {
    const replyToFree = FREE_EMAIL_PROVIDERS.has(replyToReg);
    const fromFree = FREE_EMAIL_PROVIDERS.has(fromReg);

    if (replyToFree && !fromFree) {
      senderFindings.push({
        id: 'sender-replyto-free-mismatch',
        category: 'sender_identity',
        title: 'Organizational Sender Redirects Replies to Free Webmail Account',
        severity: 'high',
        scoreImpact: 38,
        evidence: `From: ${email.fromAddress} (${fromReg}) → Reply-To: ${email.replyTo} (${replyToReg})`,
        explanation: `The email appears to come from "${fromReg}", but sets the Reply-To address to a personal free email provider ("${replyToReg}"). Attackers frequently spoof an organizational From header while directing replies to an external webmail inbox they control.`,
        recommendation: 'Do not reply to this message. Contact the sender by typing their known official address in a new message.',
      });
    } else if (isKnownEspDomain(replyToReg)) {
      senderFindings.push({
        id: 'sender-replyto-esp',
        category: 'sender_identity',
        title: 'Third-Party Service Reply-To Domain',
        severity: 'low',
        scoreImpact: 6,
        evidence: `From domain: ${fromReg} → Reply-To domain: ${replyToReg}`,
        explanation: `The Reply-To domain (${replyToReg}) differs from the From domain (${fromReg}), though ${replyToReg} is a recognized email or customer engagement platform. Legitimate marketing and ticketing systems often use separate routing domains.`,
        recommendation: 'Ensure the sender organization is one you recognize before replying.',
      });
    } else {
      senderFindings.push({
        id: 'sender-replyto-mismatch',
        category: 'sender_identity',
        title: 'Sender (From) and Reply-To Domain Mismatch',
        severity: 'medium',
        scoreImpact: 20,
        evidence: `From: ${email.from} (${fromReg}) → Reply-To: ${email.replyTo} (${replyToReg})`,
        explanation: `The Reply-To domain ("${replyToReg}") differs from the From domain ("${fromReg}"). While legitimate organizations occasionally route replies to partner domains or helpdesks, unexpected domain mismatches can redirect responses to an external party.`,
        recommendation: 'Verify whether the Reply-To domain belongs to an authorized partner of the sender organization.',
      });
    }
  }

  // 5. Compare From vs. Return-Path domain
  if (fromReg && returnPathReg && fromReg !== returnPathReg) {
    if (isKnownEspDomain(returnPathReg)) {
      senderFindings.push({
        id: 'sender-returnpath-esp',
        category: 'sender_identity',
        title: 'External Email Service Provider Return-Path',
        severity: 'info',
        scoreImpact: 0,
        evidence: `From: ${fromReg} | Return-Path: ${email.returnPath} (${returnPathReg})`,
        explanation: `The Return-Path domain (${returnPathReg}) belongs to a known Email Service Provider (ESP). Legitimate newsletters, invoices, and transactional notifications routinely use ESP bounce domains.`,
        recommendation: 'Check that SPF/DKIM authentication passes to confirm authorized sending.',
      });
    } else {
      const returnPathFree = FREE_EMAIL_PROVIDERS.has(returnPathReg);
      senderFindings.push({
        id: 'sender-returnpath-mismatch',
        category: 'sender_identity',
        title: 'Unexpected Return-Path (Envelope Sender) Domain Mismatch',
        severity: returnPathFree ? 'high' : 'medium',
        scoreImpact: returnPathFree ? 32 : 16,
        evidence: `From: ${email.fromAddress} (${fromReg}) | Return-Path: ${email.returnPath} (${returnPathReg})`,
        explanation: `The bounce/envelope sender domain in Return-Path ("${returnPathReg}") does not match the visible From domain ("${fromReg}") and is not a standard commercial ESP. This can indicate envelope spoofing or unauthorized forwarding.`,
        recommendation: 'Cross-check the SPF and DMARC alignment results before trusting the sender identity.',
      });
    }
  }

  // 6. Evaluate SPF / DKIM / DMARC findings
  const mechanisms = [spf, dkim, dmarc];
  for (const m of mechanisms) {
    if (m.result === 'fail') {
      const isDmarcFail = m.mechanism === 'DMARC';
      authFindings.push({
        id: `auth-${m.mechanism.toLowerCase()}-fail`,
        category: 'authentication',
        title: `${m.mechanism} Authentication Check Failed`,
        severity: isDmarcFail ? 'high' : 'medium',
        scoreImpact: isDmarcFail ? 38 : 26,
        evidence: `${m.mechanism}=${m.result} (${m.details})`,
        explanation: `${m.explanation} A failed ${m.mechanism} check increases spoofing concern, though forwarded emails or misconfigured servers can sometimes cause authentication failures.`,
        recommendation: `Treat the sender address with high skepticism unless verified through an out-of-band channel.`,
      });
    } else if (m.result === 'softfail') {
      authFindings.push({
        id: `auth-${m.mechanism.toLowerCase()}-softfail`,
        category: 'authentication',
        title: `${m.mechanism} Softfail Warning`,
        severity: 'medium',
        scoreImpact: 18,
        evidence: `${m.mechanism}=${m.result} (${m.details})`,
        explanation: m.explanation,
        recommendation: 'Inspect additional sender and URL indicators carefully before trusting this message.',
      });
    } else if (m.result === 'permerror' || m.result === 'temperror') {
      authFindings.push({
        id: `auth-${m.mechanism.toLowerCase()}-error`,
        category: 'authentication',
        title: `${m.mechanism} Verification Error (${m.result})`,
        severity: 'low',
        scoreImpact: 12,
        evidence: `${m.mechanism}=${m.result} (${m.details})`,
        explanation: m.explanation,
        recommendation: 'Do not rely on header authentication alone when DNS or signature evaluation encountered errors.',
      });
    } else if (m.result === 'none') {
      authFindings.push({
        id: `auth-${m.mechanism.toLowerCase()}-none`,
        category: 'authentication',
        title: `No ${m.mechanism} Policy Published by Sender`,
        severity: 'low',
        scoreImpact: 8,
        evidence: `${m.mechanism}=none`,
        explanation: m.explanation,
        recommendation: 'Be cautious when interacting with domains that lack standard email authentication policies.',
      });
    }
  }

  return {
    senderFindings,
    authFindings,
    authResults: {
      spf,
      dkim,
      dmarc,
      rawHeader: email.authenticationResults,
    },
  };
}
