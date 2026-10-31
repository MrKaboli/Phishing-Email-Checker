import { ParsedEmail, RedactionReport } from '../types/phishguard';

export interface RedactedEmailPayload {
  from: string;
  to: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  textBody: string;
  report: RedactionReport;
}

export function redactTextContent(input: string): {
  redacted: string;
  emailsCount: number;
  phonesCount: number;
  namesCount: number;
} {
  if (!input) {
    return { redacted: '', emailsCount: 0, phonesCount: 0, namesCount: 0 };
  }

  let text = input;
  let emailsCount = 0;
  let phonesCount = 0;
  let namesCount = 0;

  // 1. Redact email local-parts while preserving the security-relevant @domain
  // Avoid matching inside URLs with @ tricks (negative lookbehind for ://)
  text = text.replace(
    /(?<![:/])([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
    (_match, _localPart, domain) => {
      emailsCount++;
      return `[EMAIL_REDACTED]@${domain}`;
    }
  );

  // 2. Redact phone numbers (North American and international formats)
  text = text.replace(
    /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
    () => {
      phonesCount++;
      return '[PHONE_REDACTED]';
    }
  );

  // 3. Redact identifiable personal names in greetings and sign-offs
  // e.g., "Dear John Smith," or "Hi Sarah," or "Hello Mr. Robert Miles,"
  text = text.replace(
    /\b(Dear|Hello|Hi|Attention)\s+(?:Mr\.|Ms\.|Mrs\.|Dr\.)?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})(?=[,:\n])/g,
    (_match, greeting) => {
      namesCount++;
      return `${greeting} [NAME_REDACTED]`;
    }
  );

  // Sign-offs e.g. "Best regards,\nJohn Smith"
  text = text.replace(
    /\b(Best regards|Sincerely|Kind regards|Regards|Thanks),?\s*\r?\n\s*([A-Z][a-z]+\s+[A-Z][a-z]+)/g,
    (_match, signoff) => {
      namesCount++;
      return `${signoff},\n[NAME_REDACTED]`;
    }
  );

  return { redacted: text, emailsCount, phonesCount, namesCount };
}

export function prepareRedactedPayload(
  email: ParsedEmail,
  redactEnabled: boolean
): RedactedEmailPayload {
  if (!redactEnabled) {
    return {
      from: email.from,
      to: email.to,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      subject: email.subject,
      textBody: email.textBody,
      report: {
        enabled: false,
        emailsRedacted: 0,
        phonesRedacted: 0,
        namesRedacted: 0,
        redactedSubject: email.subject,
        redactedBodyPreview: email.textBody.slice(0, 300),
      },
    };
  }

  const fromRes = redactTextContent(email.from);
  const toRes = redactTextContent(email.to);
  const replyToRes = redactTextContent(email.replyTo);
  const returnPathRes = redactTextContent(email.returnPath);
  const subjRes = redactTextContent(email.subject);
  const bodyRes = redactTextContent(email.textBody);

  const totalEmails =
    fromRes.emailsCount +
    toRes.emailsCount +
    replyToRes.emailsCount +
    returnPathRes.emailsCount +
    subjRes.emailsCount +
    bodyRes.emailsCount;

  const totalPhones =
    fromRes.phonesCount +
    toRes.phonesCount +
    subjRes.phonesCount +
    bodyRes.phonesCount;

  const totalNames =
    fromRes.namesCount +
    toRes.namesCount +
    subjRes.namesCount +
    bodyRes.namesCount;

  return {
    from: fromRes.redacted,
    to: toRes.redacted,
    replyTo: replyToRes.redacted,
    returnPath: returnPathRes.redacted,
    subject: subjRes.redacted,
    textBody: bodyRes.redacted,
    report: {
      enabled: true,
      emailsRedacted: totalEmails,
      phonesRedacted: totalPhones,
      namesRedacted: totalNames,
      redactedSubject: subjRes.redacted,
      redactedBodyPreview: bodyRes.redacted.slice(0, 300),
    },
  };
}
