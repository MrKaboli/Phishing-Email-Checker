import { AttachmentMetadata, AnchorLinkPair, EmailScanInput, ParsedEmail } from '../types/phishguard';
import { MAX_EMAIL_SIZE_BYTES } from './config';

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

export function validateEmailInput(input: EmailScanInput): ValidationResult {
  if (input.uploadedFileName) {
    const lowerName = input.uploadedFileName.toLowerCase().trim();
    if (!lowerName.endsWith('.eml') && !lowerName.endsWith('.txt')) {
      return {
        valid: false,
        error: 'Unsupported file format. Only .eml and .txt email files are permitted.',
      };
    }
  }

  if (typeof input.uploadedFileSize === 'number') {
    if (input.uploadedFileSize === 0) {
      return { valid: false, error: 'The uploaded file is empty (0 bytes).' };
    }
    if (input.uploadedFileSize > MAX_EMAIL_SIZE_BYTES) {
      return {
        valid: false,
        error: `File size (${(input.uploadedFileSize / 1024).toFixed(1)} KB) exceeds the 100 KB security limit.`,
      };
    }
  }

  const combinedText = [
    input.rawInput || '',
    input.rawHeaders || '',
    input.subject || '',
    input.from || '',
    input.bodyText || '',
    input.bodyHtml || '',
  ]
    .join('\n')
    .trim();

  if (!combinedText && (!input.attachments || input.attachments.length === 0)) {
    return {
      valid: false,
      error: 'Email content cannot be empty. Paste email content or upload a valid .eml or .txt file.',
    };
  }

  const totalBytes = new TextEncoder().encode(combinedText).length;
  if (totalBytes > MAX_EMAIL_SIZE_BYTES) {
    return {
      valid: false,
      error: `Email payload size (${(totalBytes / 1024).toFixed(1)} KB) exceeds the maximum allowed 100 KB limit.`,
    };
  }

  return { valid: true };
}

/**
 * Decodes RFC 2047 encoded-words such as =?UTF-8?B?...?= or =?UTF-8?Q?...?=
 */
export function decodeRfc2047(text: string): string {
  if (!text || !text.includes('=?')) return text;
  try {
    return text.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g, (_match, _charset, encoding, encodedText) => {
      const enc = encoding.toUpperCase();
      if (enc === 'B') {
        try {
          if (typeof Buffer !== 'undefined') {
            return Buffer.from(encodedText, 'base64').toString('utf-8');
          }
          return decodeURIComponent(escape(atob(encodedText)));
        } catch {
          return encodedText;
        }
      }
      if (enc === 'Q') {
        const qp = encodedText
          .replace(/_/g, ' ')
          .replace(/=([0-9A-Fa-f]{2})/g, (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
        return qp;
      }
      return encodedText;
    });
  } catch {
    return text;
  }
}

export function decodeQuotedPrintable(input: string): string {
  if (!input) return '';
  try {
    // Remove soft line breaks
    const unfolded = input.replace(/=\r?\n/g, '');
    return unfolded.replace(/=([0-9A-Fa-f]{2})/g, (_match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  } catch {
    return input;
  }
}

export function extractEmailAndName(rawHeaderValue: string): {
  displayName: string;
  address: string;
  domain: string;
} {
  const cleaned = decodeRfc2047(rawHeaderValue || '').trim();
  if (!cleaned) {
    return { displayName: '', address: '', domain: '' };
  }

  // Match "Display Name" <user@domain.com>
  const angleMatch = cleaned.match(/^(?:"?([^"<]*)"?\s*)?<\s*([^>\s]+@[^>\s]+)\s*>/);
  if (angleMatch) {
    const displayName = (angleMatch[1] || '').trim().replace(/^["']|["']$/g, '');
    const address = angleMatch[2].trim().toLowerCase();
    const domain = extractDomainFromAddress(address);
    return { displayName, address, domain };
  }

  // Match bare email user@domain.com
  const bareMatch = cleaned.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (bareMatch) {
    const address = bareMatch[1].trim().toLowerCase();
    const displayName = cleaned.replace(bareMatch[0], '').replace(/[<>()"']/g, '').trim();
    const domain = extractDomainFromAddress(address);
    return { displayName, address, domain };
  }

  return { displayName: cleaned, address: '', domain: '' };
}

export function extractDomainFromAddress(emailAddress: string): string {
  if (!emailAddress || !emailAddress.includes('@')) return '';
  const parts = emailAddress.trim().toLowerCase().split('@');
  const domain = parts[parts.length - 1].replace(/[>\s"']/g, '');
  return domain;
}

export function extractAnchorLinksFromHtml(html: string): AnchorLinkPair[] {
  if (!html) return [];
  const pairs: AnchorLinkPair[] = [];
  const anchorRegex = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  let match: RegExpExecArray | null;
  while ((match = anchorRegex.exec(html)) !== null) {
    const href = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    const rawInner = match[4] || '';
    const visibleText = rawInner
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/\s+/g, ' ')
      .trim();
    if (href) {
      pairs.push({ visibleText, href });
    }
  }
  return pairs;
}

export function stripHtmlToText(html: string): string {
  if (!html) return '';
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * Looks like raw RFC-5322 email headers at the top of a text block
 */
function looksLikeRawEmailWithHeaders(raw: string): boolean {
  const firstLines = raw.trimStart().split(/\r?\n/).slice(0, 15);
  let headerLineCount = 0;
  const knownHeaders = /^(from|to|subject|date|reply-to|return-path|received|authentication-results|message-id|mime-version|content-type|dkim-signature|arc-authentication-results|x-[a-z0-9-]+)\s*:/i;

  for (const line of firstLines) {
    if (line.trim() === '') break;
    if (knownHeaders.test(line)) {
      headerLineCount++;
    }
  }
  return headerLineCount >= 2;
}

/**
 * Deterministic, synchronous parser for structured or raw MIME email input.
 * Safe against malformed MIME structures and never fetches external resources.
 */
export function parseEmailInput(input: EmailScanInput): ParsedEmail {
  const parseWarnings: string[] = [];
  const headersMap: Record<string, string> = {};
  const receivedHeaders: string[] = [];
  const authResultsList: string[] = [];
  const attachments: AttachmentMetadata[] = [...(input.attachments || [])];

  let rawHeaderSection = (input.rawHeaders || '').trim();
  let bodySection = '';
  let rawHeadersPresent = Boolean(rawHeaderSection);

  const rawInput = (input.rawInput || '').trim();

  if (rawInput) {
    if (looksLikeRawEmailWithHeaders(rawInput)) {
      rawHeadersPresent = true;
      const blankLineMatch = rawInput.match(/\r?\n\r?\n/);
      if (blankLineMatch && typeof blankLineMatch.index === 'number') {
        const extractedHeaders = rawInput.slice(0, blankLineMatch.index);
        rawHeaderSection = rawHeaderSection
          ? `${rawHeaderSection}\n${extractedHeaders}`
          : extractedHeaders;
        bodySection = rawInput.slice(blankLineMatch.index + blankLineMatch[0].length);
      } else {
        // Check if entire input is headers or malformed header block without blank line
        const lines = rawInput.split(/\r?\n/);
        const headerLines: string[] = [];
        const bodyLines: string[] = [];
        let inHeaders = true;
        for (const line of lines) {
          if (inHeaders && (/^[A-Za-z0-9-]+:\s*.*/.test(line) || (/^[ \t]+/.test(line) && headerLines.length > 0))) {
            headerLines.push(line);
          } else {
            inHeaders = false;
            bodyLines.push(line);
          }
        }
        rawHeaderSection = rawHeaderSection
          ? `${rawHeaderSection}\n${headerLines.join('\n')}`
          : headerLines.join('\n');
        bodySection = bodyLines.join('\n');
        if (bodyLines.length > 0) {
          parseWarnings.push('Malformed MIME structure: Missing standard blank line between headers and message body.');
        }
      }
    } else {
      bodySection = rawInput;
    }
  }

  // Parse unfolded headers if rawHeaderSection is present
  if (rawHeaderSection) {
    const rawLines = rawHeaderSection.split(/\r?\n/);
    const unfoldedLines: string[] = [];

    for (const line of rawLines) {
      if (/^[ \t]+/.test(line) && unfoldedLines.length > 0) {
        unfoldedLines[unfoldedLines.length - 1] += ' ' + line.trim();
      } else if (line.trim() !== '') {
        unfoldedLines.push(line);
      }
    }

    for (const line of unfoldedLines) {
      const colonIdx = line.indexOf(':');
      if (colonIdx <= 0) {
        parseWarnings.push(`Malformed header line ignored: "${line.slice(0, 60)}"`);
        continue;
      }
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const val = decodeRfc2047(line.slice(colonIdx + 1).trim());

      if (key === 'received') {
        receivedHeaders.push(val);
      } else if (key === 'authentication-results' || key === 'arc-authentication-results' || key === 'received-spf') {
        authResultsList.push(key === 'received-spf' ? `spf=${val}` : val);
      }

      if (!headersMap[key]) {
        headersMap[key] = val;
      } else {
        headersMap[key] = `${headersMap[key]}; ${val}`;
      }
    }
  }

  // Extract MIME parts if multipart or attachment headers exist in raw body
  let extractedTextBody = input.bodyText || '';
  let extractedHtmlBody = input.bodyHtml || '';

  const contentTypeHeader = headersMap['content-type'] || '';
  const boundaryMatch = contentTypeHeader.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);

  if (bodySection) {
    if (boundaryMatch) {
      const boundary = boundaryMatch[1] || boundaryMatch[2];
      const escapedBoundary = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const parts = bodySection.split(new RegExp(`--${escapedBoundary}(?:--)?`));

      // parts[0] is preamble, last part is epilogue
      for (let i = 1; i < parts.length; i++) {
        const part = parts[i].trim();
        if (!part || part === '--') continue;

        const partSplit = part.match(/\r?\n\r?\n/);
        if (!partSplit || typeof partSplit.index !== 'number') continue;

        const partHeaderRaw = part.slice(0, partSplit.index);
        let partContent = part.slice(partSplit.index + partSplit[0].length).trim();

        const partTypeMatch = partHeaderRaw.match(/Content-Type:\s*([^\r\n;]+)/i);
        const partType = (partTypeMatch ? partTypeMatch[1] : 'text/plain').trim().toLowerCase();
        const transferEncodingMatch = partHeaderRaw.match(/Content-Transfer-Encoding:\s*([^\r\n;]+)/i);
        const transferEncoding = (transferEncodingMatch ? transferEncodingMatch[1] : '').trim().toLowerCase();

        // Check for attachment filename in Content-Disposition or Content-Type
        const filenameMatch =
          partHeaderRaw.match(/filename\*?=(?:"([^"]+)"|'([^']+)'|([^;\r\n]+))/i) ||
          partHeaderRaw.match(/name=(?:"([^"]+)"|'([^']+)'|([^;\r\n]+))/i);

        if (filenameMatch) {
          const rawFilename = decodeRfc2047((filenameMatch[1] || filenameMatch[2] || filenameMatch[3] || '').trim());
          if (rawFilename && !attachments.some((a) => a.filename === rawFilename)) {
            attachments.push({
              filename: rawFilename,
              contentType: partType,
              sizeBytes: partContent.length,
            });
          }
          continue;
        }

        if (transferEncoding === 'quoted-printable') {
          partContent = decodeQuotedPrintable(partContent);
        } else if (transferEncoding === 'base64') {
          try {
            const cleanB64 = partContent.replace(/\s+/g, '');
            if (typeof Buffer !== 'undefined') {
              partContent = Buffer.from(cleanB64, 'base64').toString('utf-8');
            } else {
              partContent = decodeURIComponent(escape(atob(cleanB64)));
            }
          } catch {
            parseWarnings.push('Unable to decode base64 MIME body segment.');
          }
        }

        if (partType.includes('text/html')) {
          extractedHtmlBody += (extractedHtmlBody ? '\n' : '') + partContent;
        } else if (partType.includes('text/plain')) {
          extractedTextBody += (extractedTextBody ? '\n' : '') + partContent;
        }
      }

      if (!extractedTextBody && !extractedHtmlBody) {
        // Malformed multipart boundary fallback
        parseWarnings.push('Multipart MIME boundary declared but parts were incomplete; falling back to raw body inspection.');
        extractedTextBody = bodySection;
      }
    } else {
      // Single-part body
      let decodedBody = bodySection;
      const transferEncoding = (headersMap['content-transfer-encoding'] || '').toLowerCase();
      if (transferEncoding.includes('quoted-printable')) {
        decodedBody = decodeQuotedPrintable(decodedBody);
      } else if (transferEncoding.includes('base64')) {
        try {
          const cleanB64 = decodedBody.replace(/\s+/g, '');
          if (typeof Buffer !== 'undefined') {
            decodedBody = Buffer.from(cleanB64, 'base64').toString('utf-8');
          } else {
            decodedBody = decodeURIComponent(escape(atob(cleanB64)));
          }
        } catch {
          parseWarnings.push('Malformed base64 body encoding; inspecting raw text.');
        }
      }

      // Check if single-part header defines an attachment
      const dispHeader = headersMap['content-disposition'] || contentTypeHeader;
      const singleFileMatch =
        dispHeader.match(/filename\*?=(?:"([^"]+)"|'([^']+)'|([^;\r\n]+))/i) ||
        contentTypeHeader.match(/name=(?:"([^"]+)"|'([^']+)'|([^;\r\n]+))/i);
      if (singleFileMatch) {
        const fn = decodeRfc2047((singleFileMatch[1] || singleFileMatch[2] || singleFileMatch[3] || '').trim());
        if (fn && !attachments.some((a) => a.filename === fn)) {
          attachments.push({ filename: fn, contentType: contentTypeHeader.split(';')[0] });
        }
      }

      if (contentTypeHeader.toLowerCase().includes('text/html') || /<html|<body|<a\s+href=/i.test(decodedBody)) {
        extractedHtmlBody = extractedHtmlBody ? `${extractedHtmlBody}\n${decodedBody}` : decodedBody;
        if (!extractedTextBody) {
          extractedTextBody = stripHtmlToText(decodedBody);
        }
      } else {
        extractedTextBody = extractedTextBody ? `${extractedTextBody}\n${decodedBody}` : decodedBody;
      }
    }
  }

  // Also scan raw headers or body for inline Attachment mentions if user pasted header lines like "X-Attachment: invoice.pdf.exe" or "Attachment: invoice.pdf.exe"
  const attachmentHeaderVal = headersMap['attachment'] || headersMap['attachments'] || headersMap['x-attachment'] || '';
  if (attachmentHeaderVal) {
    for (const part of attachmentHeaderVal.split(/[,;]/)) {
      const fn = part.trim().replace(/^["']|["']$/g, '');
      if (fn && !attachments.some((a) => a.filename === fn)) {
        attachments.push({ filename: fn });
      }
    }
  }

  if (!extractedTextBody && extractedHtmlBody) {
    extractedTextBody = stripHtmlToText(extractedHtmlBody);
  }

  const rawFrom = input.from || headersMap['from'] || '';
  const parsedFrom = extractEmailAndName(rawFrom);

  const rawReplyTo = input.replyTo || headersMap['reply-to'] || '';
  const parsedReplyTo = extractEmailAndName(rawReplyTo);

  const rawReturnPath = input.returnPath || headersMap['return-path'] || '';
  const parsedReturnPath = extractEmailAndName(rawReturnPath);

  const subject = decodeRfc2047(input.subject || headersMap['subject'] || '').trim();
  const to = decodeRfc2047(input.to || headersMap['to'] || '').trim();
  const date = headersMap['date'] || '';
  const messageId = headersMap['message-id'] || '';
  const authenticationResults = authResultsList.join(' | ');

  const anchorLinks = extractAnchorLinksFromHtml(extractedHtmlBody);

  return {
    from: rawFrom.trim(),
    fromName: parsedFrom.displayName,
    fromAddress: parsedFrom.address,
    fromDomain: parsedFrom.domain,
    to,
    replyTo: rawReplyTo.trim(),
    replyToDomain: parsedReplyTo.domain,
    returnPath: rawReturnPath.trim(),
    returnPathDomain: parsedReturnPath.domain,
    subject,
    date,
    messageId,
    authenticationResults,
    receivedHeaders,
    rawHeadersPresent,
    headersMap,
    textBody: extractedTextBody.trim(),
    htmlBody: extractedHtmlBody.trim(),
    anchorLinks,
    attachments,
    parseWarnings,
  };
}
