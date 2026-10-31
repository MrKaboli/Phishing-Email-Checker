import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  Printer,
  ArrowLeft,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Lock,
  Cpu,
  EyeOff,
  Link2Off,
  Mail,
  FileWarning,
  Info,
} from 'lucide-react';
import {
  AnalysisResult,
  AuthMechanismResult,
  SeverityLevel,
} from '../types/phishguard';
import { ADVISORY_DISCLAIMER } from '../engine/config';
import { downloadJsonFile } from '../services/storageService';

interface ResultsViewProps {
  result: AnalysisResult;
  onBackToScan: () => void;
  onBackToHistory: () => void;
}

export const ResultsView: React.FC<ResultsViewProps> = ({
  result,
  onBackToScan,
  onBackToHistory,
}) => {
  const [expandedFindingIds, setExpandedFindingIds] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    result.findings.forEach((f) => {
      initial[f.id] = true;
    });
    return initial;
  });

  const toggleFinding = (id: string) => {
    setExpandedFindingIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const setAllExpanded = (open: boolean) => {
    const next: Record<string, boolean> = {};
    result.findings.forEach((f) => {
      next[f.id] = open;
    });
    setExpandedFindingIds(next);
  };

  const handleExportJson = () => {
    const exportPayload = {
      reportGenerator: 'PhishGuard AI — Intelligent Phishing Email Detector',
      exportedAt: new Date().toISOString(),
      scanMetadata: {
        scanId: result.scanId,
        timestamp: result.timestamp,
        analysisMode: result.analysisMode,
        aiModelUsed: result.aiModelUsed,
        piiRedactionEnabled: result.redaction.enabled,
      },
      verdictAssessment: {
        riskScore: result.riskScore,
        classification: result.classification.toUpperCase(),
        confidencePercentage: result.confidence,
        confidenceFactors: result.confidenceFactors,
      },
      emailMetadata: result.emailMetadata,
      authenticationHeaderEvidence: result.authResults,
      extractedUrlsDefanged: result.extractedUrls.map((u) => ({
        defangedUrl: u.defangedUrl,
        protocol: u.protocol,
        registrableDomain: u.registrableDomain,
        tld: u.tld,
        subdomainCount: u.subdomainCount,
        riskSeverity: u.riskSeverity,
        lookalikeBrand: u.lookalikeBrand || null,
        displayMismatch: u.displayMismatch || null,
      })),
      categoryBreakdown: result.categories,
      ruleBasedFindings: result.findings,
      aiContextualFindings: result.aiAnalysis,
      recommendedActions: result.recommendations,
      analysisLimitations: result.limitations,
      disclaimer: ADVISORY_DISCLAIMER,
    };

    downloadJsonFile(exportPayload, `phishguard-report-${result.scanId}.json`);
  };

  const handlePrintReport = () => {
    window.print();
  };

  // Verdict styling helpers
  const isPhishing = result.classification === 'likely_phishing';
  const isSuspicious = result.classification === 'suspicious';

  const verdictLabel = isPhishing
    ? 'LIKELY PHISHING'
    : isSuspicious
      ? 'SUSPICIOUS'
      : 'SAFE (LOW RISK)';

  const gaugeColor = isPhishing
    ? '#EF4444'
    : isSuspicious
      ? '#F59E0B'
      : '#10B981';

  const verdictTextColor = isPhishing
    ? 'text-red-400'
    : isSuspicious
      ? 'text-amber-400'
      : 'text-emerald-400';

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset =
    circumference - (Math.min(100, Math.max(0, result.riskScore)) / 100) * circumference;

  const renderSeverityLabel = (sev: SeverityLevel) => {
    if (sev === 'critical') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-bold text-red-400">
          <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
          <span>CRITICAL</span>
        </span>
      );
    }
    if (sev === 'high') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-bold text-red-400">
          <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
          <span>HIGH</span>
        </span>
      );
    }
    if (sev === 'medium') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-400">
          <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
          <span>MEDIUM</span>
        </span>
      );
    }
    if (sev === 'low') {
      return (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400">
          <Info className="w-3.5 h-3.5" aria-hidden="true" />
          <span>LOW</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
        <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
        <span>CLEAN</span>
      </span>
    );
  };

  const renderAuthBadge = (auth: AuthMechanismResult) => {
    if (auth.result === 'pass') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
          <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
          <span>PASS</span>
        </span>
      );
    }
    if (auth.result === 'fail') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400">
          <XCircle className="w-4 h-4" aria-hidden="true" />
          <span>FAIL</span>
        </span>
      );
    }
    if (auth.result === 'softfail' || auth.result === 'permerror' || auth.result === 'temperror') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
          <AlertTriangle className="w-4 h-4" aria-hidden="true" />
          <span>{auth.result.toUpperCase()}</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
        <HelpCircle className="w-4 h-4" aria-hidden="true" />
        <span>{auth.result.toUpperCase()}</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Top Action Bar (Hidden in Print) */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 bg-[#111827] border border-slate-800 rounded-xl px-5 py-4">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onBackToScan}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Scan Another Email</span>
          </button>
          <button
            type="button"
            onClick={onBackToHistory}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer"
          >
            Scan History
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={handleExportJson}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-500 hover:bg-cyan-400 rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Export JSON Report</span>
          </button>
          <button
            type="button"
            onClick={handlePrintReport}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
            <span>Print / Save PDF Report</span>
          </button>
        </div>
      </div>

      {/* Print-Only Report Header */}
      <div className="hidden print-only border-b border-slate-300 pb-4 mb-6">
        <h1 className="text-2xl font-bold text-slate-900">
          PhishGuard AI — Email Threat Assessment Report
        </h1>
        <p className="text-xs text-slate-600 font-mono mt-1">
          Scan ID: {result.scanId} · Analyzed: {new Date(result.timestamp).toLocaleString()} ·
          Mode:{' '}
          {result.analysisMode === 'full_ai_and_rules'
            ? `Full Analysis (Rules + ${result.aiModelUsed})`
            : 'Rule-Based Only'}
        </p>
      </div>

      {/* SECTION A: OVERALL VERDICT */}
      <section
        aria-label="Overall Threat Verdict"
        className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 sm:p-8"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Circular Risk Gauge */}
          <div className="lg:col-span-3 flex flex-col items-center justify-center text-center border-b lg:border-b-0 lg:border-r border-slate-800 pb-6 lg:pb-0 lg:pr-6">
            <div className="relative w-36 h-36 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke="#1E293B"
                  strokeWidth="10"
                  fill="transparent"
                />
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke={gaugeColor}
                  strokeWidth="10"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span
                  className="text-3xl font-bold font-mono tabular-nums text-slate-100"
                  data-testid="verdict-risk-score"
                >
                  {result.riskScore}
                </span>
                <span className="text-xs text-slate-400 font-mono">/ 100 RISK</span>
              </div>
            </div>

            <div
              className={`mt-3 inline-flex items-center gap-2 text-base font-bold tracking-wide ${verdictTextColor}`}
              data-testid="verdict-classification-label"
            >
              {isPhishing ? (
                <ShieldAlert className="w-5 h-5" aria-hidden="true" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-5 h-5" aria-hidden="true" />
              ) : (
                <ShieldCheck className="w-5 h-5" aria-hidden="true" />
              )}
              <span>{verdictLabel}</span>
            </div>
          </div>

          {/* Verdict Details, Mode, Redaction & Summary */}
          <div className="lg:col-span-9 space-y-5">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-300 border-b border-slate-800 pb-4">
              <span className="inline-flex items-center gap-1.5 font-medium">
                <Cpu className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                <span>
                  Mode:{' '}
                  <strong className="text-slate-100">
                    {result.analysisMode === 'full_ai_and_rules'
                      ? `Full Analysis (Rule Engine + ${result.aiModelUsed})`
                      : 'Rule-Based Only (Deterministic Engine)'}
                  </strong>
                </span>
              </span>
              <span aria-hidden="true" className="text-slate-600">
                ·
              </span>
              <span className="inline-flex items-center gap-1.5 font-mono tabular-nums">
                <span>Confidence:</span>
                <strong className="text-slate-100">{result.confidence}%</strong>
              </span>
              <span aria-hidden="true" className="text-slate-600">
                ·
              </span>
              <span className="inline-flex items-center gap-1.5">
                <EyeOff
                  className={`w-4 h-4 ${
                    result.redaction.enabled ? 'text-emerald-400' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
                <span>
                  PII Redaction:{' '}
                  <strong className="text-slate-100">
                    {result.redaction.enabled
                      ? `Enabled (${
                          result.redaction.emailsRedacted +
                          result.redaction.phonesRedacted +
                          result.redaction.namesRedacted
                        } item(s) masked before AI)`
                      : 'Disabled'}
                  </strong>
                </span>
              </span>
            </div>

            <div className="space-y-2">
              <h2 className="text-lg font-bold text-slate-100">
                Subject: {result.emailMetadata.subject}
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed">
                {result.aiAnalysis
                  ? result.aiAnalysis.summary
                  : result.findings.length > 0
                    ? `Deterministic rule analysis detected ${result.findings.length} security indicator(s). ${
                        result.aiStatusMessage || ''
                      }`
                    : `No phishing indicators were triggered by the deterministic rule engine. ${
                        result.aiStatusMessage || ''
                      }`}
              </p>
            </div>

            {/* Confidence Factors Explanation */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3.5 space-y-1.5">
              <div className="text-xs font-semibold text-slate-300">
                Evidence Completeness &amp; Confidence Factors ({result.confidence}%):
              </div>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs text-slate-400">
                {result.confidenceFactors.map((factor, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    <span className="text-cyan-400 font-mono">•</span>
                    <span>{factor}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION B: 6-CATEGORY SECURITY BREAKDOWN */}
      <section aria-label="Security Breakdown by Category" className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-slate-100">
              Multi-Layer Security Breakdown
            </h2>
            <p className="text-xs text-slate-400">
              Weighted assessment across deterministic technical modules and Gemma 4 contextual analysis
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {result.categories.map((cat) => (
            <div
              key={cat.category}
              className="print-card bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">
                    {cat.label}
                  </h3>
                  {cat.status === 'unavailable' ? (
                    <span className="text-xs font-mono text-slate-400">
                      UNAVAILABLE
                    </span>
                  ) : (
                    renderSeverityLabel(cat.severity)
                  )}
                </div>

                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                  <span>Findings: {cat.findingsCount}</span>
                  <span aria-hidden="true">·</span>
                  <span>Sub-score: {cat.score}/100</span>
                  <span aria-hidden="true">·</span>
                  <span>Weight: {cat.weight}%</span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {cat.summaryText}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 text-xs text-slate-400">
                <strong className="text-slate-300">Action:</strong>{' '}
                {cat.recommendedAction}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* SECTION C: EVIDENCE EXPLORER & DEFANGED URL INSPECTOR */}
      <section aria-label="Explainable Evidence Explorer" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100">
              Evidence Explorer ({result.findings.length} Rule Finding
              {result.findings.length === 1 ? '' : 's'})
            </h2>
            <p className="text-xs text-slate-400">
              Exact evidence extracted from the email with safely defanged URLs
              (never clickable)
            </p>
          </div>
          {result.findings.length > 0 && (
            <div className="no-print flex items-center gap-2">
              <button
                type="button"
                onClick={() => setAllExpanded(true)}
                className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded cursor-pointer"
              >
                Expand All
              </button>
              <button
                type="button"
                onClick={() => setAllExpanded(false)}
                className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded cursor-pointer"
              >
                Collapse All
              </button>
            </div>
          )}
        </div>

        {result.findings.length === 0 ? (
          <div className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 flex items-center gap-3 text-sm text-emerald-300">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <span>
              No suspicious technical or linguistic rule indicators were
              triggered in this email.
            </span>
          </div>
        ) : (
          <div className="space-y-3">
            {result.findings.map((finding) => {
              const isExpanded = Boolean(expandedFindingIds[finding.id]);
              return (
                <div
                  key={finding.id}
                  className="print-card bg-[#111827] border border-slate-800 rounded-xl overflow-hidden"
                >
                  <button
                    type="button"
                    aria-expanded={isExpanded}
                    onClick={() => toggleFinding(finding.id)}
                    className="w-full px-5 py-4 flex items-center justify-between gap-4 text-left hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <div className="flex flex-wrap items-center gap-3 min-w-0">
                      {renderSeverityLabel(finding.severity)}
                      <span className="text-sm font-semibold text-slate-100">
                        {finding.title}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-xs font-mono text-slate-400">
                        {finding.category.replace('_', ' ')}
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-slate-400" aria-hidden="true" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-400" aria-hidden="true" />
                      )}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 space-y-3 text-xs sm:text-sm">
                      <div>
                        <div className="text-xs font-semibold text-slate-400 mb-1">
                          Exact Extracted Evidence (Defanged):
                        </div>
                        <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-200 whitespace-pre-wrap break-all">
                          {finding.evidence}
                        </pre>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <div className="text-xs font-semibold text-slate-400 mb-1">
                            Why This Was Flagged:
                          </div>
                          <p className="text-slate-300 text-xs leading-relaxed">
                            {finding.explanation}
                          </p>
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-slate-400 mb-1">
                            Recommended Security Action:
                          </div>
                          <p className="text-slate-300 text-xs leading-relaxed">
                            {finding.recommendation}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Defanged URL Inspection Table */}
        {result.extractedUrls.length > 0 && (
          <div className="print-card bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Link2Off className="w-4 h-4 text-cyan-400" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-slate-100">
                Extracted &amp; Defanged URLs ({result.extractedUrls.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 pr-3 font-medium">Defanged URL (Non-Clickable)</th>
                    <th className="py-2 px-3 font-medium">Registrable Domain</th>
                    <th className="py-2 px-3 font-medium">Protocol / TLD</th>
                    <th className="py-2 pl-3 font-medium text-right">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {result.extractedUrls.map((u, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      <td className="py-2.5 pr-3 font-mono text-cyan-200 break-all max-w-md">
                        {u.defangedUrl}
                        {u.visibleText && (
                          <div className="text-slate-400 mt-0.5">
                            Visible Anchor Text: &quot;{u.visibleText}&quot;
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                        {u.registrableDomain.replace(/\./g, '[.]')}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                        {u.protocol.toUpperCase()} · .{u.tld || 'ip'} (subdomains: {u.subdomainCount})
                      </td>
                      <td className="py-2.5 pl-3 text-right whitespace-nowrap">
                        {renderSeverityLabel(u.riskSeverity)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Gemma 4 Detailed Contextual Insights */}
        {result.aiAnalysis && (
          <div className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-100">
                  Gemma 4 Contextual Second Opinion ({result.aiModelUsed})
                </h3>
              </div>
              <div className="text-xs font-mono text-slate-400 tabular-nums">
                AI Risk Score: {result.aiAnalysis.risk_score}/100 · AI Confidence:{' '}
                {result.aiAnalysis.confidence}%
              </div>
            </div>

            <p className="text-sm text-slate-200 leading-relaxed">
              {result.aiAnalysis.summary}
            </p>

            {result.aiAnalysis.social_engineering_tactics.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-300">
                  AI-Identified Social Engineering Tactics:
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.aiAnalysis.social_engineering_tactics.map((t, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1 text-xs"
                    >
                      <div className="flex items-center justify-between font-semibold text-slate-200">
                        <span className="capitalize">{t.tactic}</span>
                        <span className="uppercase font-mono text-amber-400">
                          {t.severity}
                        </span>
                      </div>
                      <div className="font-mono text-cyan-200 break-words">
                        &quot;{t.evidence}&quot;
                      </div>
                      <div className="text-slate-400">{t.explanation}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              {result.aiAnalysis.impersonation_indicators.length > 0 && (
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-slate-200">
                    Impersonation Indicators
                  </div>
                  <ul className="space-y-1 text-slate-400">
                    {result.aiAnalysis.impersonation_indicators.map((item, i) => (
                      <li key={i}>• {item}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.aiAnalysis.credential_requests.length > 0 && (
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-slate-200">
                    Credential Requests
                  </div>
                  <ul className="space-y-1 text-slate-400">
                    {result.aiAnalysis.credential_requests.map((item, i) => (
                      <li key={i}>• {item}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.aiAnalysis.financial_requests.length > 0 && (
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-slate-200">
                    Financial Requests
                  </div>
                  <ul className="space-y-1 text-slate-400">
                    {result.aiAnalysis.financial_requests.map((item, i) => (
                      <li key={i}>• {item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      {/* SECTION D: HEADER & AUTHENTICATION ANALYSIS */}
      <section
        aria-label="Header and Authentication Analysis"
        className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-5"
      >
        <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-100">
              Header Routing &amp; Authentication Evidence (SPF / DKIM / DMARC)
            </h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {result.emailMetadata.hasRawHeaders
              ? 'Full Headers Present'
              : 'Partial / Body-Only Input'}
          </span>
        </div>

        {/* Sender Identity Header Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-slate-400 font-medium">From (Visible Sender)</div>
            <div className="font-mono text-slate-100 break-all">
              {result.emailMetadata.from || 'Not provided'}
            </div>
            {result.emailMetadata.fromDomain && (
              <div className="text-cyan-400 font-mono">
                Domain: {result.emailMetadata.fromDomain}
              </div>
            )}
          </div>

          <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-slate-400 font-medium">Reply-To Header</div>
            <div className="font-mono text-slate-100 break-all">
              {result.emailMetadata.replyTo || 'None (defaults to From)'}
            </div>
            {result.emailMetadata.replyToDomain && (
              <div className="text-cyan-400 font-mono">
                Domain: {result.emailMetadata.replyToDomain}
              </div>
            )}
          </div>

          <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-slate-400 font-medium">
              Return-Path (Envelope Bounce)
            </div>
            <div className="font-mono text-slate-100 break-all">
              {result.emailMetadata.returnPath || 'Unavailable in input'}
            </div>
            {result.emailMetadata.returnPathDomain && (
              <div className="text-cyan-400 font-mono">
                Domain: {result.emailMetadata.returnPathDomain}
              </div>
            )}
          </div>
        </div>

        {/* SPF, DKIM, DMARC Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[result.authResults.spf, result.authResults.dkim, result.authResults.dmarc].map(
            (auth) => (
              <div
                key={auth.mechanism}
                className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-slate-100 font-mono">
                    {auth.mechanism}
                  </span>
                  {renderAuthBadge(auth)}
                </div>
                <div className="text-xs font-mono text-slate-300 break-words">
                  {auth.details}
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {auth.explanation}
                </p>
              </div>
            )
          )}
        </div>
      </section>

      {/* SECTION E: RECOMMENDED ACTIONS & LIMITATIONS */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-100">
              Recommended Next Steps
            </h2>
          </div>
          <ul className="space-y-2.5 text-xs sm:text-sm text-slate-200">
            {result.recommendations.map((rec, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <CheckCircle2
                  className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5"
                  aria-hidden="true"
                />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="print-card bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-amber-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-100">
              Analysis Scope &amp; Limitations
            </h2>
          </div>
          <ul className="space-y-2 text-xs text-slate-300">
            {result.limitations.map((lim, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-amber-400 font-mono">•</span>
                <span>{lim}</span>
              </li>
            ))}
          </ul>
          <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 leading-relaxed">
            {ADVISORY_DISCLAIMER}
          </div>
        </div>
      </section>
    </div>
  );
};
