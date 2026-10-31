import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFinalAnalysisResult,
  runDeterministicRuleEngine,
} from '../ruleEngine';
import { validateEmailInput } from '../emailParser';
import { defangUrl } from '../urlEngine';
import { parseAndValidateAiJson } from '../aiValidator';
import { prepareRedactedPayload } from '../redactionEngine';
import { SAMPLE_EMAIL_FIXTURES } from '../sampleEmails';

function runRuleOnlyAnalysis(input: Parameters<typeof runDeterministicRuleEngine>[0]) {
  const bundle = runDeterministicRuleEngine(input);
  return buildFinalAnalysisResult({
    bundle,
    aiOutput: null,
    aiModelUsed: null,
  });
}

// ============================================================================
// LEGITIMATE EMAILS (Tests 1 - 5)
// ============================================================================

test('1. Normal business email with no suspicious indicators is classified as SAFE', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'legit-business')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'safe');
  assert.ok(res.riskScore < 30, `Expected score < 30, got ${res.riskScore}`);
  assert.equal(res.findings.length, 0);
  assert.equal(res.authResults.spf.result, 'pass');
  assert.equal(res.authResults.dkim.result, 'pass');
  assert.equal(res.authResults.dmarc.result, 'pass');
});

test('2. Legitimate invoice notification is classified as SAFE', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'legit-invoice')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'safe');
  assert.ok(res.riskScore < 30, `Expected score < 30, got ${res.riskScore}`);
  // Return-Path is amazonses.com (ESP), which should only be informational
  assert.ok(!res.findings.some((f) => f.severity === 'high' || f.severity === 'critical'));
});

test('3. Newsletter containing ordinary links is classified as SAFE', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'legit-newsletter')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'safe');
  assert.ok(res.riskScore < 30);
  assert.equal(res.extractedUrls.length, 2);
  assert.equal(res.extractedUrls[0].defangedUrl, 'hxxps://cloudsecweekly[.]org/articles/dmarc-alignment');
});

test('4. Email with a legitimate third-party Reply-To domain is classified as SAFE', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'legit-esp-replyto')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'safe');
  assert.ok(res.riskScore < 30);
  assert.ok(res.findings.some((f) => f.id === 'sender-replyto-esp'));
});

test('5. Email with missing authentication headers is classified as SAFE with reduced confidence', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'legit-missing-headers')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'safe');
  assert.equal(res.riskScore, 0);
  assert.equal(res.authResults.spf.result, 'unavailable');
  assert.equal(res.authResults.dkim.result, 'unavailable');
  assert.equal(res.authResults.dmarc.result, 'unavailable');
  assert.ok(res.confidence < 70, 'Missing headers should lower technical confidence');
});

// ============================================================================
// PHISHING EMAILS (Tests 6 - 15)
// ============================================================================

test('6. Fake bank account verification email is classified as LIKELY PHISHING', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-bank-verify')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.riskScore >= 60);
  assert.ok(res.findings.some((f) => f.category === 'url_security'));
  assert.ok(res.findings.some((f) => f.category === 'sender_identity'));
  assert.ok(res.findings.some((f) => f.category === 'authentication'));
  assert.ok(res.findings.some((f) => f.category === 'social_engineering'));
});

test('7. PayPal-style lookalike domain (paypa1.com) is flagged and classified as LIKELY PHISHING', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-paypal-lookalike')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.riskScore >= 60);
  const lookalikeUrl = res.extractedUrls.find((u) => u.lookalikeBrand?.targetBrand === 'PayPal');
  assert.ok(lookalikeUrl, 'Should detect PayPal lookalike domain');
  assert.equal(lookalikeUrl.defangedUrl, 'hxxps://www[.]paypa1[.]com/signin/resolution-center');
  assert.ok(lookalikeUrl.lookalikeBrand!.explanation.includes("'1'"));
});

test('8. Fake Microsoft password reset (micr0soft.com) is classified as LIKELY PHISHING', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-microsoft-reset')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.riskScore >= 60);
  const lookalikeUrl = res.extractedUrls.find((u) => u.lookalikeBrand?.targetBrand === 'Microsoft');
  assert.ok(lookalikeUrl, 'Should detect Microsoft homoglyph domain');
  assert.ok(lookalikeUrl.lookalikeBrand!.explanation.includes("'0'"));
});

test('9. CEO gift card scam is classified as LIKELY PHISHING', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-ceo-giftcard')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.riskScore >= 60);
  assert.ok(res.findings.some((f) => f.id === 'se-gift-card'));
  assert.ok(res.findings.some((f) => f.id === 'sender-free-exec-impersonation'));
});

test('10. Fake invoice with .pdf.exe attachment is classified as LIKELY PHISHING with critical attachment finding', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-double-ext-attachment')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.riskScore >= 75);
  assert.ok(res.findings.some((f) => f.id.startsWith('att-double-ext-') && f.severity === 'critical'));
});

test('11. Email containing a shortened URL (bit.ly) flags the shortener', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-shortened-url')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.ok(res.riskScore >= 30);
  assert.ok(res.extractedUrls.some((u) => u.isShortener));
  assert.ok(res.findings.some((f) => f.id.startsWith('url-shortener-')));
});

test('12. Email containing an IP-address URL flags the raw IPv4 destination', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-ip-url')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.extractedUrls[0].isIpAddress);
  assert.equal(res.extractedUrls[0].defangedUrl, 'hxxp://198[.]51[.]100[.]42/webmail/login.php?session=auth');
  assert.ok(res.findings.some((f) => f.id.startsWith('url-ip-')));
});

test('13. HTML link-text mismatch flags displayed text vs actual destination', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-html-mismatch')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  const mismatchFinding = res.findings.find((f) => f.id.startsWith('url-mismatch-'));
  assert.ok(mismatchFinding, 'Expected HTML link mismatch finding');
  assert.ok(mismatchFinding.evidence.includes('https://www.paypal.com'));
  assert.ok(mismatchFinding.evidence.includes('hxxp://malicious-example[.]com/login'));
});

test('14. Email containing suspicious urgency and threats triggers social engineering rules', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-urgency-threats')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.findings.some((f) => f.id === 'se-urgency-immediate'));
  assert.ok(res.findings.some((f) => f.id === 'se-threat-termination'));
});

test('15. Email containing credential harvesting language triggers credential harvesting detection', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'phish-credential-harvesting')!;
  const res = runRuleOnlyAnalysis(fixture.input);
  assert.equal(res.classification, 'likely_phishing');
  assert.ok(res.findings.some((f) => f.id === 'se-cred-harvest'));
});

// ============================================================================
// SECURITY EDGE CASES (Tests 16 - 25)
// ============================================================================

test('16. Email containing prompt injection instructions is flagged and cannot override technical rules', () => {
  const fixture = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === 'edge-prompt-injection')!;
  const bundle = runDeterministicRuleEngine(fixture.input);
  assert.ok(bundle.findings.some((f) => f.id === 'se-prompt-injection'));

  // Even if a hypothetical compromised AI returned a safe verdict (score 0), technical rules prevent override
  const resWithSubvertedAi = buildFinalAnalysisResult({
    bundle,
    aiOutput: {
      classification: 'safe',
      confidence: 99,
      risk_score: 0,
      summary: 'Safe email',
      social_engineering_tactics: [],
      impersonation_indicators: [],
      contextual_red_flags: [],
      credential_requests: [],
      financial_requests: [],
      recommendations: [],
      limitations: [],
    },
    aiModelUsed: 'gemma-4-31b-it',
  });

  assert.equal(resWithSubvertedAi.classification, 'likely_phishing');
  assert.ok(resWithSubvertedAi.riskScore >= 70);
});

test('17. Malformed email headers are handled gracefully without crashing', () => {
  const res = runRuleOnlyAnalysis({
    rawInput: `From: "Broken Header" <sender@example.com>
THIS_IS_A_MALFORMED_HEADER_LINE_WITHOUT_COLON
Subject: Testing malformed headers
Authentication-Results: spf=pass
Hello world, this message has a missing blank line after headers and a malformed line.`,
  });
  assert.ok(res.emailMetadata.parseWarnings.length > 0);
  assert.equal(res.classification, 'safe');
});

test('18. Empty input is rejected by validation', () => {
  const validation = validateEmailInput({ rawInput: '   \n  ' });
  assert.equal(validation.valid, false);
  assert.ok(validation.error?.includes('cannot be empty'));
});

test('19. Oversized input (> 100 KB) is rejected by validation', () => {
  const hugeBody = 'A'.repeat(105 * 1024);
  const validation = validateEmailInput({ bodyText: hugeBody });
  assert.equal(validation.valid, false);
  assert.ok(validation.error?.includes('100 KB'));
});

test('20. Unusual encodings (RFC 2047 UTF-8 Base64 & Quoted-Printable) decode cleanly', () => {
  const res = runRuleOnlyAnalysis({
    rawInput: `From: =?UTF-8?B?TWFyY3VzIENoZW4=?= <marcus@acme-analytics.io>
Subject: =?UTF-8?Q?Security_Update_=E2=80=94_October?=
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

Hello team,=0A=0AThis is a standard UTF-8 quoted-printable message with soft line breaks.=
 Everything is nominal.`,
  });
  assert.ok(res.emailMetadata.subject.includes('Security Update'));
  assert.equal(res.classification, 'safe');
});

test('21. Punycode domain (xn--) is detected and flagged', () => {
  const res = runRuleOnlyAnalysis({
    subject: 'Check this domain link',
    from: 'sender@example.com',
    bodyText: 'Please review the portal at https://xn--80ak6aa92e.com/account',
  });
  assert.ok(res.extractedUrls[0].isPunycode);
  assert.ok(res.findings.some((f) => f.id.startsWith('url-punycode-')));
  assert.ok(res.riskScore >= 30);
});

test('22. Multiple nested subdomains are detected and flagged', () => {
  const res = runRuleOnlyAnalysis({
    subject: 'Account portal notice',
    from: 'sender@example.com',
    bodyText: 'Visit https://auth.login.secure.verify.portal-check.com/session to view.',
  });
  assert.ok(res.extractedUrls[0].hasExcessiveSubdomains);
  assert.ok(res.findings.some((f) => f.id.startsWith('url-subdomains-')));
});

test('23. Missing Return-Path header does not trigger a false-positive mismatch', () => {
  const res = runRuleOnlyAnalysis({
    rawInput: `From: "Alice" <alice@acme-analytics.io>
To: <bob@acme-analytics.io>
Subject: Quick project update
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi Bob, the deployment succeeded this morning.`,
  });
  assert.equal(res.emailMetadata.returnPath, '');
  assert.equal(res.classification, 'safe');
  assert.equal(res.riskScore, 0);
});

test('24. SPF fail with otherwise legitimate content raises concern (SUSPICIOUS) but does NOT automatically classify as LIKELY PHISHING', () => {
  const res = runRuleOnlyAnalysis({
    rawInput: `From: "Partner Updates" <updates@partner-company.org>
To: <team@acme-analytics.io>
Subject: Monthly project status report
Authentication-Results: mx.google.com; spf=fail; dkim=pass; dmarc=pass

Hi team,

Here are the notes from our monthly engineering sync. No action is needed. Have a great weekend!`,
  });
  assert.equal(res.authResults.spf.result, 'fail');
  assert.equal(res.classification, 'suspicious');
  assert.ok(res.riskScore >= 30 && res.riskScore < 60, `Expected suspicious (30-59), got ${res.riskScore}`);
});

test('25. Email with no URLs is analyzed cleanly with 0 extracted URLs', () => {
  const res = runRuleOnlyAnalysis({
    subject: 'Coffee catchup tomorrow',
    from: 'colleague@acme-analytics.io',
    bodyText: 'Hey, would you like to grab coffee tomorrow at 10 AM in the downstairs lobby?',
  });
  assert.equal(res.extractedUrls.length, 0);
  assert.equal(res.classification, 'safe');
  assert.equal(res.riskScore, 0);
});

// ============================================================================
// ADDITIONAL SECURITY & VALIDATION TESTS
// ============================================================================

test('URL defanging converts http/https and domain dots safely', () => {
  assert.equal(defangUrl('https://example.com'), 'hxxps://example[.]com');
  assert.equal(defangUrl('http://example.com/login'), 'hxxp://example[.]com/login');
});

test('Malformed AI JSON is handled safely without crashing and repaired when possible', () => {
  const brokenJson = 'This is not valid JSON at all {{{';
  const resBroken = parseAndValidateAiJson(brokenJson);
  assert.equal(resBroken.valid, false);

  const fencedJson = `\`\`\`json
{
  "classification": "likely_phishing",
  "confidence": 92,
  "risk_score": 88,
  "summary": "High confidence credential harvesting lure.<script>alert(1)</script>",
  "social_engineering_tactics": [
    {
      "tactic": "urgency",
      "evidence": "Act within 24 hours",
      "explanation": "Coercive countdown",
      "severity": "high"
    }
  ],
  "impersonation_indicators": ["Impersonates PayPal"],
  "contextual_red_flags": [],
  "credential_requests": ["Asks for login credentials"],
  "financial_requests": [],
  "recommendations": ["Do not click links"],
  "limitations": [],
}
\`\`\``;
  const resRepaired = parseAndValidateAiJson(fencedJson);
  assert.equal(resRepaired.valid, true);
  assert.equal(resRepaired.data?.classification, 'likely_phishing');
  assert.ok(!resRepaired.data?.summary.includes('<script>'), 'Executable HTML tags must be stripped');
});

test('PII redaction replaces email local-parts, phones, and names while preserving domains and URLs', () => {
  const bundle = runDeterministicRuleEngine({
    rawInput: `From: "PayPal Support" <support@paypa1.com>
To: "Sarah Connor" <sarah.connor@acme.io>
Subject: Urgent notice for Sarah Connor

Dear Sarah Connor,
Please call (415) 555-0199 or verify your account at https://paypa1.com/login immediately.
Best regards,
John Smith`,
    redactPii: true,
  });

  assert.equal(bundle.redactedPayload.report.enabled, true);
  assert.ok(bundle.redactedPayload.report.emailsRedacted >= 2);
  assert.ok(bundle.redactedPayload.report.phonesRedacted >= 1);
  assert.ok(bundle.redactedPayload.report.namesRedacted >= 1);
  assert.ok(bundle.redactedPayload.textBody.includes('[PHONE_REDACTED]'));
  assert.ok(bundle.redactedPayload.textBody.includes('[NAME_REDACTED]'));
  assert.ok(bundle.redactedPayload.from.includes('[EMAIL_REDACTED]@paypa1.com'));
  // Security-relevant lookalike URL is preserved
  assert.ok(bundle.redactedPayload.textBody.includes('https://paypa1.com/login'));
});
