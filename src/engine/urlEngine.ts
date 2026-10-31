import { ExtractedUrlInfo, ParsedEmail, RuleFinding, SeverityLevel } from '../types/phishguard';
import { PROTECTED_BRANDS, SUSPICIOUS_TLDS, URL_SHORTENERS } from './config';

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'co.nz',
  'co.za',
  'com.br',
  'com.sg',
  'co.in',
]);

/**
 * Safely defangs a URL for non-clickable display:
 * https://example.com -> hxxps://example[.]com
 * http://example.com  -> hxxp://example[.]com
 */
export function defangUrl(rawUrl: string): string {
  if (!rawUrl) return '';
  let trimmed = rawUrl.trim();

  // Replace scheme
  trimmed = trimmed
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://');

  // Split scheme, authority/host, and path
  const schemeMatch = trimmed.match(/^([a-zA-Z0-9+.-]+:\/\/)([^/?#]+)(.*)$/);
  if (schemeMatch) {
    const scheme = schemeMatch[1];
    const authority = schemeMatch[2].replace(/\./g, '[.]');
    const rest = schemeMatch[3];
    return `${scheme}${authority}${rest}`;
  }

  return trimmed.replace(/\./g, '[.]');
}

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,      // deletion
        dp[i][j - 1] + 1,      // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return dp[m][n];
}

/**
 * Normalizes common homoglyphs and multi-character lookalikes to detect typosquatting.
 */
export function normalizeHomoglyphs(label: string): {
  normalized: string;
  substitutions: string[];
} {
  let s = label.toLowerCase();
  const substitutions: string[] = [];

  if (s.includes('rn')) {
    substitutions.push("digraph 'rn' substituting for letter 'm'");
    s = s.replace(/rn/g, 'm');
  }
  if (s.includes('vv')) {
    substitutions.push("digraph 'vv' substituting for letter 'w'");
    s = s.replace(/vv/g, 'w');
  }
  if (s.includes('1')) {
    substitutions.push("number '1' substituting for letter 'l' or 'i'");
    s = s.replace(/1/g, 'l');
  }
  if (s.includes('0')) {
    substitutions.push("number '0' substituting for letter 'o'");
    s = s.replace(/0/g, 'o');
  }
  if (s.includes('5')) {
    substitutions.push("number '5' substituting for letter 's'");
    s = s.replace(/5/g, 's');
  }
  if (s.includes('3')) {
    substitutions.push("number '3' substituting for letter 'e'");
    s = s.replace(/3/g, 'e');
  }

  return { normalized: s, substitutions };
}

export function parseDomainComponents(hostname: string): {
  registrableDomain: string;
  tld: string;
  subdomainCount: number;
  domainLabel: string;
} {
  const cleanHost = hostname.toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanHost)) {
    return {
      registrableDomain: cleanHost,
      tld: '',
      subdomainCount: 0,
      domainLabel: cleanHost,
    };
  }

  const parts = cleanHost.split('.').filter(Boolean);
  if (parts.length < 2) {
    return {
      registrableDomain: cleanHost,
      tld: parts[0] || '',
      subdomainCount: 0,
      domainLabel: parts[0] || '',
    };
  }

  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    const registrableDomain = `${parts[parts.length - 3]}.${lastTwo}`;
    const subdomainParts = parts.slice(0, parts.length - 3).filter((p) => p !== 'www');
    return {
      registrableDomain,
      tld: lastTwo,
      subdomainCount: subdomainParts.length,
      domainLabel: parts[parts.length - 3],
    };
  }

  const registrableDomain = lastTwo;
  const subdomainParts = parts.slice(0, parts.length - 2).filter((p) => p !== 'www');
  return {
    registrableDomain,
    tld: parts[parts.length - 1],
    subdomainCount: subdomainParts.length,
    domainLabel: parts[parts.length - 2],
  };
}

export function detectLookalikeDomain(
  hostname: string,
  registrableDomain: string,
  domainLabel: string
): ExtractedUrlInfo['lookalikeBrand'] | undefined {
  const lowerHost = hostname.toLowerCase();
  const lowerReg = registrableDomain.toLowerCase();

  for (const brand of PROTECTED_BRANDS) {
    // If it IS an official domain of the brand, it is NOT a lookalike
    if (
      brand.officialDomains.some(
        (official) => lowerReg === official || lowerHost.endsWith(`.${official}`)
      )
    ) {
      return undefined;
    }
  }

  for (const brand of PROTECTED_BRANDS) {
    const target = brand.keyword;
    const officialPrimary = brand.officialDomains[0];

    // 1. Check homoglyph normalization on the primary domain label
    const { normalized, substitutions } = normalizeHomoglyphs(domainLabel);
    if (normalized === target && domainLabel !== target) {
      return {
        targetBrand: brand.name,
        officialDomain: officialPrimary,
        matchType: 'confirmed_lookalike',
        explanation: `The destination uses ${substitutions.join(' and ')} in "${registrableDomain}" to impersonate ${brand.name} (${officialPrimary}).`,
      };
    }

    //Also check if normalized label with 'i' instead of 'l' matches target
    const normalizedI = domainLabel.toLowerCase().replace(/1/g, 'i').replace(/0/g, 'o');
    if (normalizedI === target && domainLabel !== target) {
      return {
        targetBrand: brand.name,
        officialDomain: officialPrimary,
        matchType: 'confirmed_lookalike',
        explanation: `The destination uses character substitution in "${registrableDomain}" to impersonate ${brand.name} (${officialPrimary}).`,
      };
    }

    // 2. Check deceptive brand embedding with hyphens or subdomains (e.g., paypal-verify-account.com or paypal.com.security-check.xyz)
    if (
      domainLabel.includes(target) &&
      domainLabel !== target &&
      (domainLabel.includes('-') || domainLabel.length > target.length + 2)
    ) {
      return {
        targetBrand: brand.name,
        officialDomain: officialPrimary,
        matchType: 'confirmed_lookalike',
        explanation: `The domain "${registrableDomain}" embeds the protected brand name "${brand.name}" with deceptive qualifiers outside of ${officialPrimary}.`,
      };
    }

    if (lowerHost.includes(target) && !domainLabel.includes(target)) {
      return {
        targetBrand: brand.name,
        officialDomain: officialPrimary,
        matchType: 'confirmed_lookalike',
        explanation: `The hostname "${lowerHost}" places "${brand.keyword}" in a deceptive subdomain while the actual destination domain is "${registrableDomain}" (not ${officialPrimary}).`,
      };
    }

    // 3. Check Levenshtein edit distance (typosquatting like paypaI.com, amaz0n.com, microsfot.com)
    if (target.length >= 5 && Math.abs(domainLabel.length - target.length) <= 1) {
      const dist = levenshteinDistance(domainLabel.toLowerCase(), target);
      if (dist === 1) {
        return {
          targetBrand: brand.name,
          officialDomain: officialPrimary,
          matchType: substitutions.length > 0 ? 'confirmed_lookalike' : 'possible_lookalike',
          explanation: `The domain label "${domainLabel}" differs by only 1 character from "${target}" (${brand.name}'s official domain is ${officialPrimary}), indicating likely typosquatting.`,
        };
      }
      if (dist === 2 && normalized === target) {
        return {
          targetBrand: brand.name,
          officialDomain: officialPrimary,
          matchType: 'confirmed_lookalike',
          explanation: `The domain "${registrableDomain}" uses homoglyph substitution (${substitutions.join(', ')}) resembling ${brand.name} (${officialPrimary}).`,
        };
      }
    }
  }

  return undefined;
}

function inspectSingleUrl(
  rawUrl: string,
  source: ExtractedUrlInfo['source'],
  visibleText?: string
): ExtractedUrlInfo | null {
  let cleanedUrl = rawUrl.trim().replace(/[).,;!'"]+$/, '');
  if (!/^https?:\/\//i.test(cleanedUrl)) {
    return null;
  }

  // Parse URL components safely without making any network calls
  const match = cleanedUrl.match(/^(https?):\/\/([^/?#]+)([^\s]*)$/i);
  if (!match) return null;

  const protocol = match[1].toLowerCase() === 'https' ? 'https' : 'http';
  const rawAuthority = match[2];
  const pathAndQuery = match[3] || '';

  const obfuscationFlags: string[] = [];

  // Check embedded credentials or misleading @ symbol in authority
  let hostname = rawAuthority;
  if (rawAuthority.includes('@')) {
    const atParts = rawAuthority.split('@');
    const userInfo = atParts.slice(0, -1).join('@');
    hostname = atParts[atParts.length - 1];
    obfuscationFlags.push(
      `Contains misleading '@' authority prefix ("${userInfo}@") designed to disguise the actual destination host "${hostname}".`
    );
  }

  hostname = hostname.replace(/:\d+$/, '').toLowerCase();

  const isIpAddress =
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    /^0x[0-9a-f]+$/i.test(hostname);

  const { registrableDomain, tld, subdomainCount, domainLabel } = parseDomainComponents(hostname);

  const isShortener = URL_SHORTENERS.has(registrableDomain) || URL_SHORTENERS.has(hostname);
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld.toLowerCase());
  const isPunycode = hostname.includes('xn--');
  const hasExcessiveSubdomains = subdomainCount >= 3;

  // Obfuscation checks
  const encodedMatches = cleanedUrl.match(/%[0-9A-Fa-f]{2}/g) || [];
  if (encodedMatches.length >= 4) {
    obfuscationFlags.push(`Excessive percent-encoding (${encodedMatches.length} encoded sequences) detected in URL.`);
  }
  if (/[?&](redirect|redirect_uri|url|next|return|returnUrl|dest|destination|goto|continue)=https?%3A|[?&](redirect|url|next|goto)=https?:/i.test(pathAndQuery)) {
    obfuscationFlags.push('Contains open-redirect query parameter pointing to an external URL.');
  }
  if (cleanedUrl.length > 160) {
    obfuscationFlags.push(`Unusually long URL (${cleanedUrl.length} characters) often used to hide malicious parameters.`);
  }

  const lookalikeBrand = !isIpAddress
    ? detectLookalikeDomain(hostname, registrableDomain, domainLabel)
    : undefined;

  // Check HTML display text vs destination mismatch
  let displayMismatch: ExtractedUrlInfo['displayMismatch'] | undefined;
  const defangedUrl = defangUrl(cleanedUrl);

  if (visibleText) {
    const trimmedVisible = visibleText.trim();
    // Does visibleText look like a URL or domain name?
    const visibleUrlMatch = trimmedVisible.match(/^(?:https?:\/\/)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?:\/.*)?$/);
    if (visibleUrlMatch) {
      const visibleHost = visibleUrlMatch[1].toLowerCase();
      const visibleParsed = parseDomainComponents(visibleHost);
      if (
        visibleParsed.registrableDomain &&
        visibleParsed.tld.length >= 2 &&
        visibleParsed.registrableDomain !== registrableDomain
      ) {
        displayMismatch = {
          displayedText: trimmedVisible,
          actualDestinationDefanged: defangedUrl,
          reason: `The visible link text claims to lead to "${visibleParsed.registrableDomain}", but the actual underlying href points to "${registrableDomain}".`,
        };
      }
    }
  }

  // Determine highest severity for this URL
  let riskSeverity: SeverityLevel = 'info';
  if (
    displayMismatch ||
    lookalikeBrand?.matchType === 'confirmed_lookalike' ||
    isIpAddress ||
    rawAuthority.includes('@')
  ) {
    riskSeverity = 'high';
  } else if (
    lookalikeBrand?.matchType === 'possible_lookalike' ||
    isPunycode ||
    hasExcessiveSubdomains ||
    isShortener ||
    obfuscationFlags.length > 0
  ) {
    riskSeverity = 'medium';
  } else if (isSuspiciousTld || protocol === 'http') {
    riskSeverity = 'low';
  }

  return {
    originalUrl: cleanedUrl,
    defangedUrl,
    source,
    visibleText,
    protocol,
    hostname,
    registrableDomain,
    tld,
    subdomainCount,
    isIpAddress,
    isShortener,
    isSuspiciousTld,
    isPunycode,
    hasExcessiveSubdomains,
    lookalikeBrand,
    obfuscationFlags,
    displayMismatch,
    riskSeverity,
  };
}

export function analyzeUrls(email: ParsedEmail): {
  extractedUrls: ExtractedUrlInfo[];
  findings: RuleFinding[];
} {
  const extractedUrls: ExtractedUrlInfo[] = [];
  const seenKeys = new Set<string>();

  // 1. Inspect HTML anchor links first (preserves visibleText -> href pairing)
  for (const pair of email.anchorLinks) {
    const info = inspectSingleUrl(pair.href, 'html_href', pair.visibleText);
    if (info) {
      const key = `${info.originalUrl}|${info.visibleText || ''}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        extractedUrls.push(info);
      }
    }
  }

  // 2. Extract URLs from plain text body and HTML body
  const urlRegex = /https?:\/\/[^\s<>"'`]+/gi;
  const textMatches = (email.textBody || '').match(urlRegex) || [];
  for (const raw of textMatches) {
    const info = inspectSingleUrl(raw, 'text');
    if (info && !extractedUrls.some((u) => u.originalUrl === info.originalUrl)) {
      extractedUrls.push(info);
    }
  }

  const htmlMatches = (email.htmlBody || '').match(urlRegex) || [];
  for (const raw of htmlMatches) {
    const info = inspectSingleUrl(raw, 'html_text');
    if (info && !extractedUrls.some((u) => u.originalUrl === info.originalUrl)) {
      extractedUrls.push(info);
    }
  }

  // Build deduplicated RuleFindings
  const findings: RuleFinding[] = [];
  let findingIdx = 1;

  for (const u of extractedUrls) {
    if (u.displayMismatch) {
      findings.push({
        id: `url-mismatch-${findingIdx++}`,
        category: 'url_security',
        title: 'Deceptive Link Display Text vs. Destination Mismatch',
        severity: 'high',
        scoreImpact: 45,
        evidence: `Displayed text: "${u.displayMismatch.displayedText}" → Actual destination: ${u.displayMismatch.actualDestinationDefanged}`,
        explanation: u.displayMismatch.reason,
        recommendation:
          'Never trust the visible text of a hyperlink. Do not open this link; navigate to the organization website independently.',
      });
    }

    if (u.lookalikeBrand) {
      const isConfirmed = u.lookalikeBrand.matchType === 'confirmed_lookalike';
      findings.push({
        id: `url-lookalike-${findingIdx++}`,
        category: 'url_security',
        title: isConfirmed
          ? `Lookalike / Homoglyph Domain Impersonating ${u.lookalikeBrand.targetBrand}`
          : `Possible Lookalike Domain Resembling ${u.lookalikeBrand.targetBrand}`,
        severity: isConfirmed ? 'high' : 'medium',
        scoreImpact: isConfirmed ? 48 : 28,
        evidence: u.defangedUrl,
        explanation: u.lookalikeBrand.explanation,
        recommendation: `Do not open the link. Visit ${u.lookalikeBrand.targetBrand}'s official website (${u.lookalikeBrand.officialDomain}) directly via a trusted bookmark.`,
      });
    }

    if (u.isIpAddress) {
      findings.push({
        id: `url-ip-${findingIdx++}`,
        category: 'url_security',
        title: 'Raw IP Address Destination URL',
        severity: 'high',
        scoreImpact: 40,
        evidence: u.defangedUrl,
        explanation: `The link points directly to a numeric IPv4 address (${u.hostname.replace(/\./g, '[.]')}) instead of a registered domain name, a common tactic for transient phishing hosts.`,
        recommendation: 'Do not visit IP-based links sent via email. Legitimate commercial services use verifiable domain names.',
      });
    }

    if (u.isPunycode) {
      findings.push({
        id: `url-punycode-${findingIdx++}`,
        category: 'url_security',
        title: 'Internationalized Punycode Domain (xn--)',
        severity: 'high',
        scoreImpact: 35,
        evidence: u.defangedUrl,
        explanation: `The hostname "${u.hostname.replace(/\./g, '[.]')}" uses Punycode (xn--) internationalized domain encoding, which can render non-ASCII characters identical to trusted Latin domains (IDN homograph attack).`,
        recommendation: 'Verify the domain carefully before interacting, and never enter credentials on unexpected Punycode domains.',
      });
    }

    if (u.isShortener) {
      findings.push({
        id: `url-shortener-${findingIdx++}`,
        category: 'url_security',
        title: 'Obfuscated Destination via URL Shortener',
        severity: 'medium',
        scoreImpact: 24,
        evidence: u.defangedUrl,
        explanation: `The email uses a URL shortening service (${u.registrableDomain.replace(/\./g, '[.]')}) that hides the true final destination domain from inspection.`,
        recommendation: 'Avoid clicking shortened links in unexpected emails, especially those claiming account alerts or invoices.',
      });
    }

    if (u.hasExcessiveSubdomains) {
      findings.push({
        id: `url-subdomains-${findingIdx++}`,
        category: 'url_security',
        title: 'Excessive Nested Subdomain Structure',
        severity: 'medium',
        scoreImpact: 22,
        evidence: u.defangedUrl,
        explanation: `The hostname contains ${u.subdomainCount} subdomain levels under "${u.registrableDomain.replace(/\./g, '[.]')}". Phishing kits often nest deep subdomains to push the true registrable domain out of view on mobile screens.`,
        recommendation: 'Inspect the rightmost registrable domain before the first single slash (/) rather than the leading subdomain words.',
      });
    }

    if (u.obfuscationFlags.length > 0) {
      const hasAtTrick = u.obfuscationFlags.some((f) => f.includes("'@'"));
      findings.push({
        id: `url-obfuscation-${findingIdx++}`,
        category: 'url_security',
        title: hasAtTrick ? 'Deceptive @ Credential Prefix in URL' : 'URL Obfuscation or Open-Redirect Pattern',
        severity: hasAtTrick ? 'high' : 'medium',
        scoreImpact: hasAtTrick ? 42 : 20,
        evidence: u.defangedUrl,
        explanation: u.obfuscationFlags.join(' '),
        recommendation: 'Do not click obfuscated or redirect-wrapped URLs.',
      });
    }

    if (u.isSuspiciousTld) {
      findings.push({
        id: `url-tld-${findingIdx++}`,
        category: 'url_security',
        title: `Top-Level Domain (.${u.tld}) Frequently Associated with Abuse`,
        severity: 'low',
        scoreImpact: 12,
        evidence: u.defangedUrl,
        explanation: `The domain uses the ".${u.tld}" top-level domain. While not malicious on its own, this TLD is statistically prevalent in low-cost disposable phishing campaigns.`,
        recommendation: 'Treat unexpected requests from unfamiliar domains on this TLD with extra caution.',
      });
    }

    if (u.protocol === 'http' && !u.isIpAddress && !u.displayMismatch) {
      findings.push({
        id: `url-http-${findingIdx++}`,
        category: 'url_security',
        title: 'Unencrypted HTTP Link Protocol',
        severity: 'low',
        scoreImpact: 10,
        evidence: u.defangedUrl,
        explanation: 'The link uses unencrypted HTTP (hxxp://) rather than HTTPS, meaning any transmitted data is sent in cleartext.',
        recommendation: 'Never submit login credentials or sensitive data over an unencrypted HTTP connection.',
      });
    }
  }

  return { extractedUrls, findings };
}
