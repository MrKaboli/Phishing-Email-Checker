import React from 'react';
import {
  BookOpen,
  Link2Off,
  ShieldCheck,
  AlertTriangle,
  LifeBuoy,
  Lock,
  MailWarning,
  ScanSearch,
} from 'lucide-react';
import { ADVISORY_DISCLAIMER } from '../engine/config';

interface SecurityGuideViewProps {
  onNavigateToScan: (sampleId?: string) => void;
}

export const SecurityGuideView: React.FC<SecurityGuideViewProps> = ({
  onNavigateToScan,
}) => {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-2 text-xs font-semibold text-cyan-400">
            <BookOpen className="w-4 h-4" aria-hidden="true" />
            <span>Cybersecurity Field Guide</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100">
            Understanding &amp; Defending Against Phishing
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            A practical, plain-language reference explaining how modern email
            threats operate, how to read technical headers, and what steps to
            take if you encounter a suspected attack.
          </p>
        </div>

        <button
          type="button"
          onClick={() => onNavigateToScan('phish-paypal-lookalike')}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs sm:text-sm rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0 self-start md:self-auto"
        >
          <ScanSearch className="w-4 h-4" aria-hidden="true" />
          <span>Test a Sample Phishing Email</span>
        </button>
      </div>

      {/* 1. What Phishing Is & 2. How Phishing Works */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center gap-2.5">
            <MailWarning className="w-5 h-5 text-cyan-400 shrink-0" aria-hidden="true" />
            <h2 className="text-lg font-bold text-slate-100">
              01. What Is Phishing &amp; How It Works
            </h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            <strong>Phishing</strong> is a form of social engineering where
            attackers impersonate trusted organizations, colleagues, executives,
            or government agencies to trick recipients into revealing passwords,
            approving fraudulent payments, or opening malware attachments.
          </p>
          <p className="text-sm text-slate-300 leading-relaxed">
            Instead of exploiting software vulnerabilities directly, phishing
            exploits human trust and urgency:
          </p>
          <ul className="space-y-2 text-xs sm:text-sm text-slate-300 pt-1">
            <li>
              • <strong>The Lure:</strong> A convincing pretext (e.g., an
              unauthorized login alert, a failed invoice payment, or an urgent
              request from a CEO).
            </li>
            <li>
              • <strong>The Hook:</strong> A deceptive hyperlink leading to a
              replica login page, a reply-to trap, or a disguised attachment
              like <code className="font-mono text-cyan-300">invoice.pdf.exe</code>.
            </li>
            <li>
              • <strong>The Catch:</strong> Harvesting your entered credentials,
              session tokens, gift card PINs, or wire transfers.
            </li>
          </ul>
        </section>

        {/* 3. Common Phishing Warning Signs */}
        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" aria-hidden="true" />
            <h2 className="text-lg font-bold text-slate-100">
              02. Common Phishing Warning Signs
            </h2>
          </div>
          <ul className="space-y-2.5 text-xs sm:text-sm text-slate-300">
            <li>
              • <strong>Artificial Urgency &amp; Threats:</strong> Demands to act
              within 24 hours to prevent account termination, legal action, or
              service suspension.
            </li>
            <li>
              • <strong>Sender &amp; Reply-To Mismatches:</strong> A message
              displaying a company name (e.g. &quot;CEO David Thornton&quot;)
              sent from a personal <code className="font-mono text-amber-300">@gmail.com</code>{' '}
              address, or redirecting replies to an unrelated domain.
            </li>
            <li>
              • <strong>Irreversible Payment Requests:</strong> Requests to buy
              retail gift cards (Apple, Steam, Google Play) and scratch off the
              PINs, or last-minute changes to vendor wire routing numbers.
            </li>
            <li>
              • <strong>Dangerous File Extensions:</strong> Attachments ending in{' '}
              <code className="font-mono text-red-300">.exe</code>,{' '}
              <code className="font-mono text-red-300">.scr</code>,{' '}
              <code className="font-mono text-red-300">.hta</code>,{' '}
              <code className="font-mono text-red-300">.iso</code>, or
              macro-enabled <code className="font-mono text-red-300">.docm/.xlsm</code>.
            </li>
          </ul>
        </section>
      </div>

      {/* 4. How to Identify Fake Links */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <Link2Off className="w-5 h-5 text-cyan-400 shrink-0" aria-hidden="true" />
          <h2 className="text-lg font-bold text-slate-100">
            03. How to Identify Fake &amp; Deceptive Links
          </h2>
        </div>
        <p className="text-sm text-slate-300">
          Attackers use several techniques to make malicious links appear
          trustworthy at a glance. PhishGuard AI automatically defangs URLs (converting{' '}
          <code className="font-mono text-cyan-300">https://example.com</code> to{' '}
          <code className="font-mono text-cyan-300">hxxps://example[.]com</code>)
          so you can inspect them safely without accidental clicks.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <div className="font-semibold text-slate-100">
              1. Homoglyphs &amp; Lookalikes
            </div>
            <div className="font-mono text-red-300">
              hxxps://paypa1[.]com
              <br />
              hxxps://arnazon[.]com
            </div>
            <p className="text-slate-400 leading-relaxed">
              Replaces <code className="font-mono">l</code> with{' '}
              <code className="font-mono">1</code>, <code className="font-mono">o</code>{' '}
              with <code className="font-mono">0</code>, or{' '}
              <code className="font-mono">m</code> with{' '}
              <code className="font-mono">rn</code>.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <div className="font-semibold text-slate-100">
              2. Display Text vs. Href Mismatch
            </div>
            <div className="font-mono text-red-300">
              Text: paypal.com
              <br />
              Href: evil-site[.]org
            </div>
            <p className="text-slate-400 leading-relaxed">
              HTML emails allow any visible text over a completely different
              destination URL.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <div className="font-semibold text-slate-100">
              3. Deep Subdomain Padding
            </div>
            <div className="font-mono text-amber-300">
              paypal.login.verify.evil[.]com
            </div>
            <p className="text-slate-400 leading-relaxed">
              Always read the domain immediately to the left of the first single
              slash (<code className="font-mono">evil.com</code>).
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <div className="font-semibold text-slate-100">
              4. Punycode &amp; Shorteners
            </div>
            <div className="font-mono text-amber-300">
              hxxps://xn--80ak6aa92e[.]com
              <br />
              hxxps://bit[.]ly/3x9KpL2
            </div>
            <p className="text-slate-400 leading-relaxed">
              Internationalized <code className="font-mono">xn--</code> domains
              and URL shorteners hide the true destination.
            </p>
          </div>
        </div>
      </section>

      {/* 5 & 6. SPF, DKIM, DMARC and Why Passing Auth != Safe */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
          <h2 className="text-lg font-bold text-slate-100">
            04. What SPF, DKIM, and DMARC Mean — And Why &quot;PASS&quot; Does Not Guarantee Safety
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs sm:text-sm">
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <h3 className="font-bold text-slate-100 font-mono">
              SPF (Sender Policy Framework)
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Specifies which mail server IP addresses are authorized to send
              email on behalf of a domain. If an unauthorized server sends mail,
              SPF reports <code className="font-mono text-red-300">fail</code> or{' '}
              <code className="font-mono text-amber-300">softfail</code>.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <h3 className="font-bold text-slate-100 font-mono">
              DKIM (DomainKeys Identified Mail)
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Attaches a cryptographic digital signature to the email headers,
              proving the domain owner signed the message and that headers/body
              were not altered in transit.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5">
            <h3 className="font-bold text-slate-100 font-mono">
              DMARC (Domain-based Message Auth)
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Ensures that the visible <code className="font-mono">From</code>{' '}
              domain aligns with the authenticated SPF and/or DKIM domain, and
              tells receiving servers how to handle failures.
            </p>
          </div>
        </div>

        <div className="p-4 bg-amber-950/30 border border-amber-500/30 rounded-lg space-y-1.5 text-xs sm:text-sm">
          <div className="font-semibold text-amber-300">
            Critical Security Insight: Why Email Authentication Does NOT Guarantee Legitimacy
          </div>
          <p className="text-slate-300 text-xs leading-relaxed">
            1. <strong>Free Webmail Accounts Pass Authentication:</strong> When a
            scammer creates a free <code className="font-mono">@gmail.com</code>{' '}
            account and sets their display name to &quot;CEO David Thornton&quot;,
            Google’s servers legitimately sign the message—so SPF, DKIM, and
            DMARC all report <strong>PASS</strong>.<br />
            2. <strong>Attacker-Registered Domains:</strong> An attacker who
            purchases <code className="font-mono">paypa1.com</code> can configure
            valid SPF, DKIM, and DMARC records for <code className="font-mono">paypa1.com</code>.<br />
            3. <strong>Compromised Legitimate Accounts:</strong> If a vendor’s
            real email account is hijacked, phishing emails sent from their
            account will pass all authentication checks.
          </p>
        </div>
      </section>

      {/* 7 & 8. Incident Response Playbooks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center gap-2.5">
            <Lock className="w-5 h-5 text-cyan-400 shrink-0" aria-hidden="true" />
            <h2 className="text-lg font-bold text-slate-100">
              05. What To Do After Receiving a Suspicious Email
            </h2>
          </div>
          <ol className="space-y-2 text-xs sm:text-sm text-slate-300 list-decimal list-inside">
            <li>
              <strong>Do not click links or open attachments</strong> inside the
              message.
            </li>
            <li>
              <strong>Do not reply</strong> or call phone numbers listed inside
              the email body.
            </li>
            <li>
              <strong>Verify out-of-band:</strong> Contact the person or company
              using a phone number or website bookmark you obtained independently.
            </li>
            <li>
              <strong>Report the message</strong> to your IT Security team or
              email provider’s &quot;Report Phishing&quot; tool.
            </li>
            <li>
              <strong>Delete the email</strong> once it has been reported.
            </li>
          </ol>
        </section>

        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center gap-2.5">
            <LifeBuoy className="w-5 h-5 text-red-400 shrink-0" aria-hidden="true" />
            <h2 className="text-lg font-bold text-slate-100">
              06. What To Do If You Already Clicked a Link or Entered Details
            </h2>
          </div>
          <ol className="space-y-2 text-xs sm:text-sm text-slate-300 list-decimal list-inside">
            <li>
              <strong>Change your password immediately</strong> on the official
              website from a trusted device (and anywhere else you reused that
              password).
            </li>
            <li>
              <strong>Revoke active sessions &amp; enable MFA:</strong> Sign out
              of all active sessions in your account security settings and
              enable hardware or app-based Multi-Factor Authentication.
            </li>
            <li>
              <strong>Disconnect &amp; scan if a file was downloaded:</strong> If
              you opened an attachment, disconnect from the network and run a
              full endpoint antivirus/EDR scan.
            </li>
            <li>
              <strong>Notify your organization or bank:</strong> Immediately
              alert your IT security helpdesk (for work accounts) or your bank’s
              fraud department (if financial data was entered).
            </li>
          </ol>
        </section>
      </div>

      <div className="text-xs text-slate-400 bg-[#111827] border border-slate-800 rounded-xl p-4">
        {ADVISORY_DISCLAIMER}
      </div>
    </div>
  );
};
