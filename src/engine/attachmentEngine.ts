import { AttachmentMetadata, ParsedEmail, RuleFinding } from '../types/phishguard';
import { DANGEROUS_EXTENSIONS } from './config';

const BENIGN_DECOY_EXTENSIONS = new Set([
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'jpg',
  'jpeg',
  'png',
  'txt',
  'csv',
  'mp4',
]);

function inspectSingleAttachment(att: AttachmentMetadata, index: number): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const rawName = (att.filename || '').trim();
  if (!rawName) return findings;

  const lowerName = rawName.toLowerCase();
  const dotParts = lowerName.split('.').filter(Boolean);

  if (dotParts.length < 2) {
    return findings;
  }

  const finalExt = `.${dotParts[dotParts.length - 1]}`;
  const prevExt = dotParts.length >= 3 ? dotParts[dotParts.length - 2] : '';

  // 1. Check Double Extension masquerading (e.g. invoice.pdf.exe, document.docx.scr, payment.jpg.js)
  if (
    prevExt &&
    BENIGN_DECOY_EXTENSIONS.has(prevExt) &&
    (DANGEROUS_EXTENSIONS.executables.has(finalExt) ||
      DANGEROUS_EXTENSIONS.diskImages.has(finalExt) ||
      DANGEROUS_EXTENSIONS.htmlWeb.has(finalExt))
  ) {
    findings.push({
      id: `att-double-ext-${index}`,
      category: 'attachment_security',
      title: `Deceptive Double-Extension Masquerading (${rawName})`,
      severity: 'critical',
      scoreImpact: 65,
      evidence: `Attachment filename: "${rawName}" (decoy ".${prevExt}" followed by executable "${finalExt}")`,
      explanation: `The file "${rawName}" uses a double extension to disguise an executable or active script ("${finalExt}") as a benign ".${prevExt}" document. Operating systems that hide known extensions display this file as "${rawName.slice(0, rawName.length - finalExt.length)}".`,
      recommendation:
        'Do not download, open, or execute this attachment under any circumstances. Quarantine or delete the email immediately.',
    });
    return findings; // Avoid double-counting the same executable extension
  }

  // 2. Check Executable files
  if (DANGEROUS_EXTENSIONS.executables.has(finalExt)) {
    findings.push({
      id: `att-exec-${index}`,
      category: 'attachment_security',
      title: `High-Risk Executable or Script Attachment (${finalExt})`,
      severity: 'critical',
      scoreImpact: 58,
      evidence: `Attachment filename: "${rawName}"`,
      explanation: `The attachment "${rawName}" is an executable binary or script (${finalExt}) capable of running arbitrary code and installing malware on your system.`,
      recommendation: 'Never open or run executable files (.exe, .scr, .bat, .ps1, .vbs, .js) received via email.',
    });
  } else if (DANGEROUS_EXTENSIONS.diskImages.has(finalExt)) {
    // 3. Disk images (.iso, .img)
    findings.push({
      id: `att-disk-${index}`,
      category: 'attachment_security',
      title: `Mountable Disk Image Attachment (${finalExt})`,
      severity: 'high',
      scoreImpact: 42,
      evidence: `Attachment filename: "${rawName}"`,
      explanation: `Disk image files (${finalExt}) are frequently used in malware campaigns because mounting them can bypass Mark-of-the-Web (MotW) browser security warnings.`,
      recommendation: 'Do not mount or open unexpected .iso or .img files.',
    });
  } else if (DANGEROUS_EXTENSIONS.macroOffice.has(finalExt)) {
    // 4. Macro-enabled Office documents
    findings.push({
      id: `att-macro-${index}`,
      category: 'attachment_security',
      title: `Macro-Enabled Office Document (${finalExt})`,
      severity: 'high',
      scoreImpact: 40,
      evidence: `Attachment filename: "${rawName}"`,
      explanation: `The attachment "${rawName}" uses a macro-enabled Microsoft Office format (${finalExt}) that can execute embedded VBA macro code when opened.`,
      recommendation: 'Do not enable macros or "Enable Content" on Office documents received via email.',
    });
  } else if (DANGEROUS_EXTENSIONS.htmlWeb.has(finalExt)) {
    // 5. HTML / HTA smuggling attachments
    findings.push({
      id: `att-html-${index}`,
      category: 'attachment_security',
      title: `HTML Application / Local Web Smuggling Attachment (${finalExt})`,
      severity: finalExt === '.hta' ? 'critical' : 'high',
      scoreImpact: finalExt === '.hta' ? 55 : 36,
      evidence: `Attachment filename: "${rawName}"`,
      explanation: `Attached ${finalExt} files are commonly used for credential harvesting (rendering fake local login forms in your browser) or HTML smuggling.`,
      recommendation: 'Do not open attached .html, .htm, or .hta files or enter passwords into forms opened from local attachments.',
    });
  } else if (DANGEROUS_EXTENSIONS.archives.has(finalExt)) {
    // 6. Archive files (.zip, .rar, .7z)
    findings.push({
      id: `att-archive-${index}`,
      category: 'attachment_security',
      title: `Compressed Archive Attachment (${finalExt}) — Uninspected Contents`,
      severity: 'medium',
      scoreImpact: 22,
      evidence: `Attachment filename: "${rawName}"`,
      explanation: `The email contains a compressed archive (${finalExt}). Attackers often wrap executables or scripts inside archives (sometimes password-protected) to evade gateway scanners. Note: The internal contents of this archive have not been extracted or inspected.`,
      recommendation: 'Verify the sender independently before extracting any archive, and scan extracted files before opening.',
    });
  }

  return findings;
}

export function analyzeAttachments(email: ParsedEmail): RuleFinding[] {
  const findings: RuleFinding[] = [];
  email.attachments.forEach((att, idx) => {
    findings.push(...inspectSingleAttachment(att, idx + 1));
  });
  return findings;
}
