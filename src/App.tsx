import React, { useState, useEffect, useCallback } from 'react';
import {
  Menu,
  X,
  ScanSearch,
} from 'lucide-react';
import {
  AnalysisResult,
  EmailScanInput,
  ScanHistoryEntry,
  UserPreferences,
} from './types/phishguard';
import { ADVISORY_DISCLAIMER } from './engine/config';
import { storageService } from './services/storageService';
import {
  analyzeEmailRequest,
  fetchServerHealth,
  HealthStatus,
} from './services/apiClient';
import { DashboardView } from './components/DashboardView';
import { ScanEmailView } from './components/ScanEmailView';
import { ResultsView } from './components/ResultsView';
import { ScanHistoryView } from './components/ScanHistoryView';
import { SecurityGuideView } from './components/SecurityGuideView';
import { SettingsView } from './components/SettingsView';

type ActiveTab =
  | 'dashboard'
  | 'scan'
  | 'history'
  | 'guide'
  | 'settings'
  | 'results';

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [history, setHistory] = useState<ScanHistoryEntry[]>(() =>
    storageService.getHistory()
  );
  const [preferences, setPreferences] = useState<UserPreferences>(() =>
    storageService.getPreferences()
  );
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(
    null
  );
  const [pendingSampleId, setPendingSampleId] = useState<string | null>(null);
  const [serverHealth, setServerHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    fetchServerHealth().then(setServerHealth);
  }, []);

  const handleUpdatePreferences = useCallback((next: UserPreferences) => {
    setPreferences(next);
    storageService.savePreferences(next);
  }, []);

  const handleNavigateToScan = useCallback((sampleId?: string) => {
    if (sampleId) {
      setPendingSampleId(sampleId);
    }
    setActiveTab('scan');
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const handleRunScan = useCallback(async (input: EmailScanInput) => {
    const result = await analyzeEmailRequest(input);
    const updatedHistory = storageService.saveScan(result);
    setHistory(updatedHistory);
    setCurrentResult(result);
    setActiveTab('results');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const handleOpenScanResult = useCallback((entry: ScanHistoryEntry) => {
    setCurrentResult(entry.fullResult);
    setActiveTab('results');
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const handleDeleteScan = useCallback((scanId: string) => {
    const updated = storageService.deleteScan(scanId);
    setHistory(updated);
  }, []);

  const handleClearAllHistory = useCallback(() => {
    storageService.clearHistory();
    setHistory([]);
  }, []);

  const navItems: { id: Exclude<ActiveTab, 'results'>; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'scan', label: 'Scan Email' },
    { id: 'history', label: 'Scan History' },
    { id: 'guide', label: 'Security Guide' },
    { id: 'settings', label: 'Settings' },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-[#0B1120] text-slate-100">
      {/* Top Bar Contract: Zone 1 (Wordmark) — Zone 2 (5 Nav Links) — Zone 3 (1 Primary CTA) */}
      <header className="no-print sticky top-0 z-30 bg-[#0B1120]/95 backdrop-blur border-b border-slate-800">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-8 px-4 sm:px-6 py-4">
          {/* Zone 1: Single text element wordmark */}
          <a
            href="#dashboard"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('dashboard');
              setMobileMenuOpen(false);
            }}
            className="text-lg sm:text-xl font-bold tracking-tight text-slate-100 font-display whitespace-nowrap shrink-0 hover:text-cyan-400 transition-colors"
          >
            PhishGuard AI
          </a>

          {/* Zone 2: 5 clean single-line text navigation links */}
          <nav
            aria-label="Primary Navigation"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300"
          >
            {navItems.map((item) => {
              const isActive =
                activeTab === item.id ||
                (activeTab === 'results' && item.id === 'scan');
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(item.id);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }}
                  className={`py-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer border-b-2 ${
                    isActive
                      ? 'text-cyan-400 border-cyan-400 font-semibold'
                      : 'text-slate-300 border-transparent hover:text-white hover:border-slate-600'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: 1 primary action + mobile menu button */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => handleNavigateToScan()}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-500 hover:bg-cyan-400 rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              <ScanSearch className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Scan Email</span>
            </button>

            <button
              type="button"
              aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={mobileMenuOpen}
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              className="md:hidden p-2 rounded-lg text-slate-300 hover:text-white bg-slate-900 border border-slate-800 cursor-pointer"
            >
              {mobileMenuOpen ? (
                <X className="w-5 h-5" aria-hidden="true" />
              ) : (
                <Menu className="w-5 h-5" aria-hidden="true" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <nav
            aria-label="Mobile Navigation"
            className="md:hidden border-t border-slate-800 bg-[#0F172A] px-4 py-3 space-y-1"
          >
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 font-semibold'
                      : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>
        )}
      </header>

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8">
        {activeTab === 'dashboard' && (
          <DashboardView
            history={history}
            onNavigateToScan={handleNavigateToScan}
            onNavigateToHistory={() => setActiveTab('history')}
            onNavigateToGuide={() => setActiveTab('guide')}
            onOpenScanResult={handleOpenScanResult}
          />
        )}

        {activeTab === 'scan' && (
          <ScanEmailView
            preferences={preferences}
            onUpdatePreferences={handleUpdatePreferences}
            onRunScan={handleRunScan}
            initialSampleId={pendingSampleId}
            onClearInitialSample={() => setPendingSampleId(null)}
          />
        )}

        {activeTab === 'results' && currentResult && (
          <ResultsView
            result={currentResult}
            onBackToScan={() => setActiveTab('scan')}
            onBackToHistory={() => setActiveTab('history')}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistoryView
            history={history}
            onOpenScanResult={handleOpenScanResult}
            onDeleteScan={handleDeleteScan}
            onClearAllHistory={handleClearAllHistory}
            onNavigateToScan={() => handleNavigateToScan()}
          />
        )}

        {activeTab === 'guide' && (
          <SecurityGuideView onNavigateToScan={handleNavigateToScan} />
        )}

        {activeTab === 'settings' && (
          <SettingsView
            preferences={preferences}
            onUpdatePreferences={handleUpdatePreferences}
            serverHealth={serverHealth}
            historyCount={history.length}
            onClearAllHistory={handleClearAllHistory}
          />
        )}
      </main>

      {/* Quiet Footer with Mandatory Advisory Disclaimer */}
      <footer className="no-print border-t border-slate-800/80 bg-[#090E1A] py-6 px-4 sm:px-6 mt-12">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs text-slate-400">
          <p className="max-w-4xl leading-relaxed">{ADVISORY_DISCLAIMER}</p>
          <div className="whitespace-nowrap shrink-0 font-mono text-slate-500">
            PhishGuard AI · v1.0.0
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
