import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ScanSearch,
  ArrowRight,
  Clock,
  FileSearch,
  BookOpen,
  Info,
} from 'lucide-react';
import { ScanHistoryEntry, VerdictClassification } from '../types/phishguard';
import { ADVISORY_DISCLAIMER } from '../engine/config';

interface DashboardViewProps {
  history: ScanHistoryEntry[];
  onNavigateToScan: (sampleId?: string) => void;
  onNavigateToHistory: () => void;
  onNavigateToGuide: () => void;
  onOpenScanResult: (entry: ScanHistoryEntry) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  history,
  onNavigateToScan,
  onNavigateToHistory,
  onNavigateToGuide,
  onOpenScanResult,
}) => {
  const totalScanned = history.length;
  const likelyPhishingCount = history.filter(
    (h) => h.classification === 'likely_phishing'
  ).length;
  const suspiciousCount = history.filter(
    (h) => h.classification === 'suspicious'
  ).length;
  const safeCount = history.filter((h) => h.classification === 'safe').length;

  const recentScans = history.slice(0, 6);

  const getPct = (count: number) =>
    totalScanned > 0 ? Math.round((count / totalScanned) * 100) : 0;

  const renderVerdictLabel = (verdict: VerdictClassification) => {
    if (verdict === 'likely_phishing') {
      return (
        <span className="inline-flex items-center gap-1.5 font-medium text-red-400">
          <ShieldAlert className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>Likely Phishing</span>
        </span>
      );
    }
    if (verdict === 'suspicious') {
      return (
        <span className="inline-flex items-center gap-1.5 font-medium text-amber-400">
          <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>Suspicious</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 font-medium text-emerald-400">
        <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span>Safe (Low Risk)</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Top Hero / Quick Action Banner */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 sm:p-8 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="text-xs font-medium text-cyan-400 tracking-wide">
            Email Threat Intelligence &amp; Inspection
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight">
            Detect threats before they reach you.
          </h1>
          <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
            Combine deterministic RFC-5322 header, URL defanging, and homoglyph
            inspection with Google Gemma 4 contextual analysis to uncover
            credential harvesting, brand spoofing, and social engineering.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => onNavigateToScan()}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <ScanSearch className="w-4 h-4" aria-hidden="true" />
            <span>Quick Scan Email</span>
          </button>
          <button
            type="button"
            onClick={onNavigateToGuide}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800/80 hover:bg-slate-800 text-slate-200 border border-slate-700 font-medium text-sm rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <BookOpen className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <span>Security Guide</span>
          </button>
        </div>
      </section>

      {/* Real Scan Statistics Grid */}
      <section aria-label="Scan Statistics">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Total Emails Scanned</span>
              <FileSearch className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            </div>
            <div
              className="mt-3 text-3xl font-bold text-slate-100 font-mono tabular-nums"
              data-testid="stat-total-scanned"
            >
              {totalScanned}
            </div>
            <div className="mt-1 text-xs text-slate-400">
              Saved in local browser history
            </div>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Likely Phishing (60–100)</span>
              <ShieldAlert className="w-4 h-4 text-red-400" aria-hidden="true" />
            </div>
            <div
              className="mt-3 text-3xl font-bold text-red-400 font-mono tabular-nums"
              data-testid="stat-likely-phishing"
            >
              {likelyPhishingCount}
            </div>
            <div className="mt-1 text-xs text-slate-400 tabular-nums">
              {getPct(likelyPhishingCount)}% of scanned messages
            </div>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Suspicious (30–59)</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" aria-hidden="true" />
            </div>
            <div
              className="mt-3 text-3xl font-bold text-amber-400 font-mono tabular-nums"
              data-testid="stat-suspicious"
            >
              {suspiciousCount}
            </div>
            <div className="mt-1 text-xs text-slate-400 tabular-nums">
              {getPct(suspiciousCount)}% of scanned messages
            </div>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Safe / Low Risk (0–29)</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            </div>
            <div
              className="mt-3 text-3xl font-bold text-emerald-400 font-mono tabular-nums"
              data-testid="stat-safe"
            >
              {safeCount}
            </div>
            <div className="mt-1 text-xs text-slate-400 tabular-nums">
              {getPct(safeCount)}% of scanned messages
            </div>
          </div>
        </div>
      </section>

      {/* Empty State vs Populated Risk Distribution + Recent Scans */}
      {totalScanned === 0 ? (
        <section className="bg-[#111827] border border-slate-800 rounded-xl p-8 sm:p-10 text-center space-y-6">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto">
            <ScanSearch className="w-6 h-6 text-cyan-400" aria-hidden="true" />
          </div>
          <div className="space-y-2 max-w-lg mx-auto">
            <h2 className="text-xl font-semibold text-slate-100">
              No emails have been scanned yet
            </h2>
            <p className="text-sm text-slate-400 leading-relaxed">
              Your dashboard metrics and risk distribution chart are populated
              exclusively from real scans. Paste an email, upload a{' '}
              <code className="text-slate-300 font-mono">.eml</code> or{' '}
              <code className="text-slate-300 font-mono">.txt</code> file, or
              inspect one of our curated threat samples to begin.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => onNavigateToScan()}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm rounded-lg transition-colors cursor-pointer"
            >
              <span>Scan Your First Email</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={() => onNavigateToScan('phish-paypal-lookalike')}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-sm rounded-lg transition-colors cursor-pointer"
            >
              <span>Load PayPal Lookalike Sample</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigateToScan('legit-business')}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-sm rounded-lg transition-colors cursor-pointer"
            >
              <span>Load Legitimate Email Sample</span>
            </button>
          </div>
        </section>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Distribution Chart Card */}
          <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  Risk Distribution
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Breakdown across {totalScanned} saved scan{totalScanned === 1 ? '' : 's'}
                </p>
              </div>

              {/* Stacked Horizontal Distribution Bar */}
              <div
                className="h-4 w-full rounded-lg bg-slate-900 overflow-hidden flex border border-slate-800"
                role="img"
                aria-label={`Risk distribution: ${getPct(likelyPhishingCount)}% Likely Phishing, ${getPct(suspiciousCount)}% Suspicious, ${getPct(safeCount)}% Safe`}
              >
                {likelyPhishingCount > 0 && (
                  <div
                    style={{ width: `${(likelyPhishingCount / totalScanned) * 100}%` }}
                    className="bg-red-500 h-full transition-all"
                    title={`Likely Phishing: ${likelyPhishingCount}`}
                  />
                )}
                {suspiciousCount > 0 && (
                  <div
                    style={{ width: `${(suspiciousCount / totalScanned) * 100}%` }}
                    className="bg-amber-500 h-full transition-all"
                    title={`Suspicious: ${suspiciousCount}`}
                  />
                )}
                {safeCount > 0 && (
                  <div
                    style={{ width: `${(safeCount / totalScanned) * 100}%` }}
                    className="bg-emerald-500 h-full transition-all"
                    title={`Safe: ${safeCount}`}
                  />
                )}
              </div>

              {/* Individual Category Meters */}
              <div className="space-y-3 pt-2">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" aria-hidden="true" />
                      Likely Phishing (Score 60–100)
                    </span>
                    <span className="font-mono tabular-nums text-slate-300">
                      {likelyPhishingCount} ({getPct(likelyPhishingCount)}%)
                    </span>
                  </div>
                  <div className="h-2 w-full bg-slate-900 rounded overflow-hidden">
                    <div
                      className="h-full bg-red-500 rounded"
                      style={{ width: `${getPct(likelyPhishingCount)}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                      Suspicious (Score 30–59)
                    </span>
                    <span className="font-mono tabular-nums text-slate-300">
                      {suspiciousCount} ({getPct(suspiciousCount)}%)
                    </span>
                  </div>
                  <div className="h-2 w-full bg-slate-900 rounded overflow-hidden">
                    <div
                      className="h-full bg-amber-500 rounded"
                      style={{ width: `${getPct(suspiciousCount)}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                      Safe / Low Risk (Score 0–29)
                    </span>
                    <span className="font-mono tabular-nums text-slate-300">
                      {safeCount} ({getPct(safeCount)}%)
                    </span>
                  </div>
                  <div className="h-2 w-full bg-slate-900 rounded overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded"
                      style={{ width: `${getPct(safeCount)}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
              <span>Average Risk Score</span>
              <span className="font-mono tabular-nums text-sm font-semibold text-slate-200">
                {Math.round(
                  history.reduce((acc, item) => acc + item.riskScore, 0) /
                    totalScanned
                )}{' '}
                / 100
              </span>
            </div>
          </section>

          {/* Recent Scans Table */}
          <section className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-100">
                    Recent Scans
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Select any record to inspect full explainable evidence
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onNavigateToHistory}
                  className="text-xs font-medium text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer whitespace-nowrap shrink-0"
                >
                  <span>View All ({totalScanned})</span>
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-xs text-slate-400">
                      <th className="py-2.5 pr-4 font-medium">Subject &amp; Sender</th>
                      <th className="py-2.5 px-3 font-medium">Classification</th>
                      <th className="py-2.5 px-3 font-medium text-right">Risk Score</th>
                      <th className="py-2.5 pl-3 font-medium text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 text-sm">
                    {recentScans.map((scan) => (
                      <tr
                        key={scan.scanId}
                        className="hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="py-3 pr-4 max-w-[260px]">
                          <div className="font-medium text-slate-200 truncate">
                            {scan.subject}
                          </div>
                          <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5 truncate">
                            <span className="font-mono">{scan.senderDomain}</span>
                            <span aria-hidden="true">·</span>
                            <span className="tabular-nums">
                              {new Date(scan.timestamp).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit',
                              })}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-3 whitespace-nowrap text-xs">
                          {renderVerdictLabel(scan.classification)}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums font-semibold text-slate-200">
                          {scan.riskScore}/100
                        </td>
                        <td className="py-3 pl-3 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => onOpenScanResult(scan)}
                            className="text-xs font-medium text-cyan-400 hover:text-cyan-300 px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 transition-colors cursor-pointer"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* Security Awareness & Advisory Disclaimer */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex items-start gap-4">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0 mt-0.5">
            <Clock className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-slate-200">
              Security Awareness Tip: Verify Urgent Financial &amp; Credential Requests Out-of-Band
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Attackers rely on manufactured urgency—such as 24-hour account
              suspension threats or "in a board meeting" executive gift card
              requests—to bypass critical verification. Always confirm wire
              instructions, password resets, or sensitive changes via a known
              phone number or bookmark.
            </p>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex items-start gap-4">
          <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
            <Info className="w-4 h-4 text-slate-300" aria-hidden="true" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-slate-200">
              Advisory Security Analysis Disclaimer
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              {ADVISORY_DISCLAIMER}
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
