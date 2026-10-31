import React, { useState, useMemo } from 'react';
import {
  Search,
  Trash2,
  Download,
  ArrowUpDown,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  FolderOpen,
} from 'lucide-react';
import { ScanHistoryEntry, VerdictClassification } from '../types/phishguard';
import { downloadJsonFile } from '../services/storageService';

interface ScanHistoryViewProps {
  history: ScanHistoryEntry[];
  onOpenScanResult: (entry: ScanHistoryEntry) => void;
  onDeleteScan: (scanId: string) => void;
  onClearAllHistory: () => void;
  onNavigateToScan: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  history,
  onOpenScanResult,
  onDeleteScan,
  onClearAllHistory,
  onNavigateToScan,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'all' | VerdictClassification>('all');
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  const filteredAndSorted = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = history.filter((item) => {
      if (filterVerdict !== 'all' && item.classification !== filterVerdict) {
        return false;
      }
      if (!q) return true;
      return (
        item.subject.toLowerCase().includes(q) ||
        item.senderDomain.toLowerCase().includes(q) ||
        item.senderDisplay.toLowerCase().includes(q) ||
        item.scanId.toLowerCase().includes(q)
      );
    });

    return list.sort((a, b) => {
      const tA = new Date(a.timestamp).getTime();
      const tB = new Date(b.timestamp).getTime();
      return sortOrder === 'newest' ? tB - tA : tA - tB;
    });
  }, [history, searchQuery, filterVerdict, sortOrder]);

  const handleExportAllJson = () => {
    downloadJsonFile(
      {
        exportedAt: new Date().toISOString(),
        totalScans: history.length,
        scans: history,
      },
      `phishguard-history-${new Date().toISOString().slice(0, 10)}.json`
    );
  };

  const handleExportSingleJson = (entry: ScanHistoryEntry) => {
    downloadJsonFile(entry.fullResult, `phishguard-scan-${entry.scanId}.json`);
  };

  const renderVerdictCell = (verdict: VerdictClassification) => {
    if (verdict === 'likely_phishing') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400">
          <ShieldAlert className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>Likely Phishing</span>
        </span>
      );
    }
    if (verdict === 'suspicious') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
          <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>Suspicious</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
        <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span>Safe (Low Risk)</span>
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header & Global History Actions */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
            Scan History
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Review past threat assessments stored locally in your browser. Raw
            email bodies are omitted by default to protect privacy.
          </p>
        </div>

        {history.length > 0 && (
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleExportAllJson}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-500 hover:bg-cyan-400 rounded-lg transition-colors cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export All History (JSON)</span>
            </button>

            {!confirmClearAll ? (
              <button
                type="button"
                onClick={() => setConfirmClearAll(true)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-red-300 bg-red-950/50 hover:bg-red-900/60 border border-red-500/30 rounded-lg transition-colors cursor-pointer whitespace-nowrap"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Clear All History</span>
              </button>
            ) : (
              <div className="flex items-center gap-2 bg-red-950/70 border border-red-500/40 px-3 py-1.5 rounded-lg">
                <span className="text-xs text-red-200 font-medium">
                  Confirm delete all?
                </span>
                <button
                  type="button"
                  onClick={() => {
                    onClearAllHistory();
                    setConfirmClearAll(false);
                  }}
                  className="px-2.5 py-1 text-xs font-bold bg-red-500 hover:bg-red-400 text-slate-950 rounded cursor-pointer"
                >
                  Yes, Clear
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClearAll(false)}
                  className="px-2 py-1 text-xs text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Search, Filter & Sort Toolbar */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="relative flex-1">
          <Search
            className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2"
            aria-hidden="true"
          />
          <input
            type="search"
            aria-label="Search scan history by subject, sender domain, or scan ID"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by subject, sender domain, or scan ID..."
            className="w-full pl-9 pr-4 py-2 text-xs sm:text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Segmented Classification Filter */}
          <div
            className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg"
            role="group"
            aria-label="Filter by Classification"
          >
            {(
              [
                { value: 'all', label: 'All' },
                { value: 'likely_phishing', label: 'Likely Phishing' },
                { value: 'suspicious', label: 'Suspicious' },
                { value: 'safe', label: 'Safe' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setFilterVerdict(opt.value)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                  filterVerdict === opt.value
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'text-slate-300 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Sort Order Toggle */}
          <button
            type="button"
            onClick={() =>
              setSortOrder((prev) => (prev === 'newest' ? 'oldest' : 'newest'))
            }
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
            <span>Sort: {sortOrder === 'newest' ? 'Newest First' : 'Oldest First'}</span>
          </button>
        </div>
      </div>

      {/* History List / Empty State */}
      {history.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-10 text-center space-y-4">
          <FolderOpen
            className="w-10 h-10 text-slate-500 mx-auto"
            aria-hidden="true"
          />
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-slate-200">
              No saved scans in history
            </h2>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Every email you analyze is automatically recorded here with its
              verdict, risk score, and explainable findings.
            </p>
          </div>
          <button
            type="button"
            onClick={onNavigateToScan}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
          >
            Scan an Email Now
          </button>
        </div>
      ) : filteredAndSorted.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-8 text-center text-sm text-slate-400">
          No scan records match your current search or classification filter.
        </div>
      ) : (
        <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-xs text-slate-400">
                  <th className="py-3 px-4 font-medium">Timestamp &amp; ID</th>
                  <th className="py-3 px-4 font-medium">Subject &amp; Sender Domain</th>
                  <th className="py-3 px-4 font-medium">Verdict</th>
                  <th className="py-3 px-4 font-medium text-right">Risk / Conf.</th>
                  <th className="py-3 px-4 font-medium">Mode &amp; Findings</th>
                  <th className="py-3 px-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs sm:text-sm">
                {filteredAndSorted.map((item) => (
                  <tr
                    key={item.scanId}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap font-mono tabular-nums text-xs text-slate-300">
                      <div>{new Date(item.timestamp).toLocaleDateString()}</div>
                      <div className="text-slate-500">
                        {new Date(item.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}{' '}
                        · {item.scanId}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-semibold text-slate-100 truncate">
                        {item.subject}
                      </div>
                      <div className="text-xs text-slate-400 font-mono truncate mt-0.5">
                        {item.senderDomain}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {renderVerdictCell(item.classification)}
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap font-mono tabular-nums">
                      <div className="font-bold text-slate-100">
                        {item.riskScore}/100
                      </div>
                      <div className="text-xs text-slate-400">
                        Conf: {item.confidence}%
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-xs text-slate-300">
                      <div>
                        {item.analysisMode === 'full_ai_and_rules'
                          ? `Rules + ${item.aiModelUsed || 'Gemma 4'}`
                          : 'Rules Only'}
                      </div>
                      <div className="text-slate-400 font-mono tabular-nums">
                        {item.findingsSummary.totalFindings} finding(s)
                        {item.redactionEnabled ? ' · PII Redacted' : ''}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onOpenScanResult(item)}
                          aria-label={`Open detailed results for ${item.subject}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 rounded-md transition-colors cursor-pointer"
                        >
                          <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Open</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleExportSingleJson(item)}
                          aria-label={`Export JSON report for ${item.subject}`}
                          className="p-1.5 text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors cursor-pointer"
                          title="Export JSON"
                        >
                          <Download className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onDeleteScan(item.scanId)}
                          aria-label={`Delete scan ${item.subject}`}
                          className="p-1.5 text-red-400 hover:text-red-300 bg-red-950/40 hover:bg-red-900/50 rounded-md transition-colors cursor-pointer"
                          title="Delete Scan"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
