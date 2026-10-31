import React, { useState } from 'react';
import {
  Cpu,
  EyeOff,
  Trash2,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Info,
  Lock,
} from 'lucide-react';
import { UserPreferences } from '../types/phishguard';
import { HealthStatus } from '../services/apiClient';
import { redactTextContent } from '../engine/redactionEngine';
import { ADVISORY_DISCLAIMER } from '../engine/config';

interface SettingsViewProps {
  preferences: UserPreferences;
  onUpdatePreferences: (prefs: UserPreferences) => void;
  serverHealth: HealthStatus | null;
  historyCount: number;
  onClearAllHistory: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  preferences,
  onUpdatePreferences,
  serverHealth,
  historyCount,
  onClearAllHistory,
}) => {
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearedBanner, setClearedBanner] = useState(false);
  const [sampleRedactionText, setSampleRedactionText] = useState(
    'Dear Sarah Connor,\nPlease call (415) 555-0199 or email support@paypa1.com regarding your account.'
  );

  const liveRedactionPreview = redactTextContent(sampleRedactionText);

  const effectiveMode =
    preferences.aiAnalysisEnabled && (serverHealth?.aiConfigured ?? true)
      ? `Full Analysis: Deterministic Rule Engine + Google Gemma 4 (${preferences.preferredGemmaModel})`
      : 'Rule-Based Only: Local Deterministic Security Engine';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6">
        <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
          Settings &amp; Privacy Controls
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Configure Gemma 4 AI second-opinion analysis, automatic PII redaction,
          and local browser storage.
        </p>
      </div>

      {/* Analysis Engine & Model Configuration */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <Cpu className="w-5 h-5 text-cyan-400" aria-hidden="true" />
            <div>
              <h2 className="text-base font-bold text-slate-100">
                AI Threat Analysis Engine (Google Gemma 4)
              </h2>
              <p className="text-xs text-slate-400">
                All AI requests execute strictly through the backend server and
                never expose API keys to the browser.
              </p>
            </div>
          </div>

          <span className="text-xs font-mono text-cyan-400">
            {preferences.aiAnalysisEnabled ? 'AI Enabled' : 'Rule-Only Mode'}
          </span>
        </div>

        {/* Toggle 1: AI Analysis Enabled/Disabled */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="space-y-1">
            <label
              htmlFor="toggle-ai-analysis"
              className="text-sm font-semibold text-slate-100 cursor-pointer"
            >
              Enable Gemma 4 AI Contextual Second Opinion
            </label>
            <p className="text-xs text-slate-400 max-w-2xl">
              When enabled, PhishGuard AI combines deterministic local rule
              findings with contextual analysis from Gemma 4. When disabled, the
              application performs full rule-based scanning with zero external
              API calls.
            </p>
          </div>
          <input
            id="toggle-ai-analysis"
            type="checkbox"
            checked={preferences.aiAnalysisEnabled}
            onChange={(e) =>
              onUpdatePreferences({
                ...preferences,
                aiAnalysisEnabled: e.target.checked,
              })
            }
            className="w-5 h-5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500 cursor-pointer shrink-0"
          />
        </div>

        {/* Model Selection Display */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-2">
            <label
              htmlFor="gemma-model-select"
              className="block text-xs font-semibold text-slate-300"
            >
              Gemma 4 Model Selection
            </label>
            <select
              id="gemma-model-select"
              value={preferences.preferredGemmaModel}
              onChange={(e) =>
                onUpdatePreferences({
                  ...preferences,
                  preferredGemmaModel: e.target.value as UserPreferences['preferredGemmaModel'],
                })
              }
              className="w-full px-3 py-2 text-xs sm:text-sm font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="gemma-4-31b-it">
                gemma-4-31b-it (Preferred — 31B Instruct)
              </option>
              <option value="gemma-4-26b-a4b-it">
                gemma-4-26b-a4b-it (Alternative — 26B MoE Instruct)
              </option>
            </select>
            <p className="text-xs text-slate-400">
              Server Default Environment Model:{' '}
              <code className="font-mono text-slate-200">
                {serverHealth?.configuredModel || 'gemma-4-31b-it'}
              </code>
            </p>
          </div>

          <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-2">
            <div className="text-xs font-semibold text-slate-300">
              Current Active Analysis Mode
            </div>
            <div className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              {preferences.aiAnalysisEnabled ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" aria-hidden="true" />
              )}
              <span>{effectiveMode}</span>
            </div>
            <p className="text-xs text-slate-400">
              If the selected Gemma 4 model is temporarily unreachable, scans
              automatically fall back to the deterministic rule engine and
              renormalize scoring weights.
            </p>
          </div>
        </div>
      </section>

      {/* Privacy & Redaction Controls */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex items-center gap-2.5 border-b border-slate-800 pb-4">
          <EyeOff className="w-5 h-5 text-emerald-400" aria-hidden="true" />
          <div>
            <h2 className="text-base font-bold text-slate-100">
              Privacy &amp; Personal Information Redaction
            </h2>
            <p className="text-xs text-slate-400">
              Protect sensitive recipient details while preserving cybersecurity
              indicators and suspicious domains.
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="space-y-1">
            <label
              htmlFor="toggle-pii-redaction"
              className="text-sm font-semibold text-slate-100 cursor-pointer"
            >
              Redact personal information before AI analysis
            </label>
            <p className="text-xs text-slate-400 max-w-2xl">
              Replaces email local-parts with{' '}
              <code className="font-mono text-emerald-300">[EMAIL_REDACTED]</code>{' '}
              (while keeping <code className="font-mono">@domain.com</code> intact),
              phone numbers with{' '}
              <code className="font-mono text-emerald-300">[PHONE_REDACTED]</code>,
              and personal names in greetings/signatures with{' '}
              <code className="font-mono text-emerald-300">[NAME_REDACTED]</code>{' '}
              before sending data to Gemma 4.
            </p>
          </div>
          <input
            id="toggle-pii-redaction"
            type="checkbox"
            checked={preferences.redactPiiBeforeAi}
            onChange={(e) =>
              onUpdatePreferences({
                ...preferences,
                redactPiiBeforeAi: e.target.checked,
              })
            }
            className="w-5 h-5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500 cursor-pointer shrink-0"
          />
        </div>

        {/* Interactive Redaction Verification Sandbox */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label
              htmlFor="redaction-preview-input"
              className="block text-xs font-semibold text-slate-300"
            >
              Test Redaction Engine (Input Text):
            </label>
            <textarea
              id="redaction-preview-input"
              rows={3}
              value={sampleRedactionText}
              onChange={(e) => setSampleRedactionText(e.target.value)}
              className="w-full p-3 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="space-y-1.5">
            <div className="text-xs font-semibold text-slate-300">
              Redacted Output Sent to AI (Preserves Domains &amp; URLs):
            </div>
            <pre className="p-3 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-emerald-300 whitespace-pre-wrap min-h-[76px]">
              {liveRedactionPreview.redacted}
            </pre>
          </div>
        </div>
      </section>

      {/* Local History Storage & Application Information */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-100">
              Scan History &amp; Data Retention
            </h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            PhishGuard AI stores scan summaries locally in your browser’s{' '}
            <code className="font-mono">localStorage</code>. Complete raw email
            bodies are never persisted in history by default, and no email
            content is ever sent to third-party analytics services.
          </p>

          <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800">
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              Saved Scan Records: {historyCount}
            </span>

            {!confirmClear ? (
              <button
                type="button"
                disabled={historyCount === 0}
                onClick={() => setConfirmClear(true)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-red-300 bg-red-950/50 hover:bg-red-900/60 disabled:opacity-40 border border-red-500/30 rounded-lg transition-colors cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Clear Scan History</span>
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    onClearAllHistory();
                    setConfirmClear(false);
                    setClearedBanner(true);
                    setTimeout(() => setClearedBanner(false), 3000);
                  }}
                  className="px-3 py-1.5 text-xs font-bold bg-red-500 hover:bg-red-400 text-slate-950 rounded-md cursor-pointer"
                >
                  Confirm Clear ({historyCount})
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClear(false)}
                  className="px-2.5 py-1.5 text-xs text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>

          {clearedBanner && (
            <div className="text-xs text-emerald-400 font-medium">
              All local scan history has been permanently cleared.
            </div>
          )}
        </section>

        <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-100">
              Application &amp; Security Architecture Info
            </h2>
          </div>
          <dl className="grid grid-cols-2 gap-y-2.5 text-xs">
            <dt className="text-slate-400">Application Name</dt>
            <dd className="text-slate-100 font-semibold">PhishGuard AI</dd>

            <dt className="text-slate-400">Version</dt>
            <dd className="text-slate-100 font-mono">1.0.0</dd>

            <dt className="text-slate-400">Deterministic Engine</dt>
            <dd className="text-slate-100 font-mono">Local Rule Engine v1.0</dd>

            <dt className="text-slate-400">AI Threat Engine</dt>
            <dd className="text-slate-100 font-mono">
              Google Gemma 4 ({preferences.preferredGemmaModel})
            </dd>

            <dt className="text-slate-400">API Key Handling</dt>
            <dd className="text-emerald-400 font-medium">
              Server-Side Only (Protected)
            </dd>
          </dl>
          <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-start gap-2">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{ADVISORY_DISCLAIMER}</span>
          </div>
        </section>
      </div>
    </div>
  );
};
