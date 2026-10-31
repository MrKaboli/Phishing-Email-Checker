export const MAX_EMAIL_SIZE_BYTES = 100 * 1024; // 100 KB

export const DEFAULT_GEMMA_MODEL = 'gemma-4-31b-it';
export const FALLBACK_GEMMA_MODEL = 'gemma-4-26b-a4b-it';
export const SUPPORTED_GEMMA_MODELS = ['gemma-4-31b-it', 'gemma-4-26b-a4b-it'] as const;

export const RISK_THRESHOLDS = {
  SAFE_MAX: 29,
  SUSPICIOUS_MAX: 59,
  // 60 - 100 is LIKELY PHISHING
};

export const INITIAL_CATEGORY_WEIGHTS = {
  url_security: 0.25,
  sender_identity: 0.20,
  authentication: 0.15,
  social_engineering: 0.15,
  attachment_security: 0.15,
  ai_contextual: 0.10,
} as const;

export const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'cutt.ly',
  'shorturl.at',
  'ow.ly',
  'rb.gy',
  'rebrand.ly',
  'tiny.cc',
  'buff.ly',
  'bl.ink',
  's.id',
  'v.gd',
]);

export const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'zip',
  'mov',
  'click',
  'work',
  'loan',
  'support',
  'account',
  'update',
  'verify',
  'icu',
  'buzz',
  'sbs',
  'cfd',
  'rest',
  'fit',
]);

export interface ProtectedBrand {
  name: string;
  keyword: string;
  officialDomains: string[];
}

export const PROTECTED_BRANDS: ProtectedBrand[] = [
  { name: 'PayPal', keyword: 'paypal', officialDomains: ['paypal.com', 'paypal-communication.com'] },
  { name: 'Microsoft', keyword: 'microsoft', officialDomains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'microsoftonline.com'] },
  { name: 'Amazon', keyword: 'amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazonses.com', 'aws.amazon.com'] },
  { name: 'Google', keyword: 'google', officialDomains: ['google.com', 'gmail.com', 'accounts.google.com', 'youtube.com'] },
  { name: 'Apple', keyword: 'apple', officialDomains: ['apple.com', 'icloud.com'] },
  { name: 'Netflix', keyword: 'netflix', officialDomains: ['netflix.com'] },
  { name: 'Chase Bank', keyword: 'chase', officialDomains: ['chase.com', 'jpmorganchase.com'] },
  { name: 'Wells Fargo', keyword: 'wellsfargo', officialDomains: ['wellsfargo.com'] },
  { name: 'Bank of America', keyword: 'bankofamerica', officialDomains: ['bankofamerica.com', 'bofa.com'] },
  { name: 'Citibank', keyword: 'citibank', officialDomains: ['citi.com', 'citibank.com'] },
  { name: 'DocuSign', keyword: 'docusign', officialDomains: ['docusign.com', 'docusign.net'] },
  { name: 'DHL', keyword: 'dhl', officialDomains: ['dhl.com'] },
  { name: 'FedEx', keyword: 'fedex', officialDomains: ['fedex.com'] },
  { name: 'UPS', keyword: 'ups', officialDomains: ['ups.com'] },
  { name: 'Dropbox', keyword: 'dropbox', officialDomains: ['dropbox.com', 'dropboxmail.com'] },
  { name: 'Stripe', keyword: 'stripe', officialDomains: ['stripe.com'] },
  { name: 'GitHub', keyword: 'github', officialDomains: ['github.com'] },
  { name: 'Coinbase', keyword: 'coinbase', officialDomains: ['coinbase.com'] },
  { name: 'LinkedIn', keyword: 'linkedin', officialDomains: ['linkedin.com', 'licdn.com'] },
];

export const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'ymail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
  'mail.com',
  'gmx.com',
  'yandex.com',
  'zoho.com',
]);

export const LEGITIMATE_ESP_DOMAINS = new Set([
  'sendgrid.net',
  'amazonses.com',
  'mailchimp.com',
  'mcsv.net',
  'mandrillapp.com',
  'mailgun.org',
  'postmarkapp.com',
  'hubspotemail.net',
  'constantcontact.com',
  'substack.com',
  'Intercom-mail.com',
  'intercom-mail.com',
  'sparkpostmail.com',
  'klaviyomail.com',
  'salesforce.com',
]);

export const DANGEROUS_EXTENSIONS = {
  executables: new Set(['.exe', '.scr', '.bat', '.cmd', '.com', '.msi', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.jar', '.pif']),
  diskImages: new Set(['.iso', '.img', '.dmg', '.vhd', '.vhdx']),
  htmlWeb: new Set(['.html', '.htm', '.hta', '.svg', '.mhtml']),
  macroOffice: new Set(['.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.ppsm']),
  archives: new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.cab']),
};

export const ADVISORY_DISCLAIMER =
  'PhishGuard AI provides advisory security analysis based on available email content and headers. It cannot guarantee that an email is safe or malicious. A low-risk result does not guarantee legitimacy. Always verify sensitive requests through independently obtained official communication channels.';
