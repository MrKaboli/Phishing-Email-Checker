import {
  AnalysisResult,
  ScanHistoryEntry,
  UserPreferences,
} from '../types/phishguard';
import { DEFAULT_GEMMA_MODEL } from '../engine/config';

const HISTORY_STORAGE_KEY = 'phishguard_scan_history_v1';
const PREFS_STORAGE_KEY = 'phishguard_user_prefs_v1';
const MAX_HISTORY_ITEMS = 100;

export const DEFAULT_PREFERENCES: UserPreferences = {
  aiAnalysisEnabled: true,
  redactPiiBeforeAi: true,
  preferredGemmaModel: DEFAULT_GEMMA_MODEL,
  includeRawMetadataInExport: false,
};

/**
 * Storage repository interface designed so it can be swapped with Firebase/Firestore later.
 */
export interface IPhishGuardStorage {
  getHistory(): ScanHistoryEntry[];
  saveScan(result: AnalysisResult): ScanHistoryEntry[];
  deleteScan(scanId: string): ScanHistoryEntry[];
  clearHistory(): void;
  getPreferences(): UserPreferences;
  savePreferences(prefs: UserPreferences): void;
}

class LocalStorageRepository implements IPhishGuardStorage {
  getHistory(): ScanHistoryEntry[] {
    try {
      const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(
        (item) =>
          item &&
          typeof item.scanId === 'string' &&
          typeof item.riskScore === 'number' &&
          typeof item.classification === 'string'
      );
    } catch {
      // Gracefully recover from corrupted localStorage
      return [];
    }
  }

  saveScan(result: AnalysisResult): ScanHistoryEntry[] {
    const current = this.getHistory();
    const highOrCriticalCount = result.findings.filter(
      (f) => f.severity === 'high' || f.severity === 'critical'
    ).length;

    // Strip any raw body preview from stored history to protect privacy by default
    const sanitizedResult: AnalysisResult = {
      ...result,
      redaction: {
        ...result.redaction,
        redactedBodyPreview: '[Not persisted in local history by default]',
      },
    };

    const entry: ScanHistoryEntry = {
      scanId: result.scanId,
      timestamp: result.timestamp,
      subject: result.emailMetadata.subject || '(No Subject)',
      senderDomain: result.emailMetadata.fromDomain || 'unknown-domain',
      senderDisplay: result.emailMetadata.from || 'Unknown Sender',
      riskScore: result.riskScore,
      classification: result.classification,
      confidence: result.confidence,
      analysisMode: result.analysisMode,
      aiModelUsed: result.aiModelUsed,
      redactionEnabled: result.redaction.enabled,
      findingsSummary: {
        totalFindings: result.findings.length,
        highOrCriticalCount,
        topTitles: result.findings.slice(0, 3).map((f) => f.title),
      },
      fullResult: sanitizedResult,
    };

    const updated = [
      entry,
      ...current.filter((item) => item.scanId !== result.scanId),
    ].slice(0, MAX_HISTORY_ITEMS);

    try {
      window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Handle storage quota exceeded by keeping most recent 25
      try {
        window.localStorage.setItem(
          HISTORY_STORAGE_KEY,
          JSON.stringify(updated.slice(0, 25))
        );
      } catch {
        // Ignore if storage is disabled in browser
      }
    }

    return updated;
  }

  deleteScan(scanId: string): ScanHistoryEntry[] {
    const updated = this.getHistory().filter((item) => item.scanId !== scanId);
    try {
      window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Ignore storage write errors
    }
    return updated;
  }

  clearHistory(): void {
    try {
      window.localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // Ignore storage errors
    }
  }

  getPreferences(): UserPreferences {
    try {
      const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
      if (!raw) return DEFAULT_PREFERENCES;
      const parsed = JSON.parse(raw);
      return {
        aiAnalysisEnabled:
          typeof parsed.aiAnalysisEnabled === 'boolean'
            ? parsed.aiAnalysisEnabled
            : DEFAULT_PREFERENCES.aiAnalysisEnabled,
        redactPiiBeforeAi:
          typeof parsed.redactPiiBeforeAi === 'boolean'
            ? parsed.redactPiiBeforeAi
            : DEFAULT_PREFERENCES.redactPiiBeforeAi,
        preferredGemmaModel:
          parsed.preferredGemmaModel === 'gemma-4-26b-a4b-it'
            ? 'gemma-4-26b-a4b-it'
            : 'gemma-4-31b-it',
        includeRawMetadataInExport: Boolean(parsed.includeRawMetadataInExport),
      };
    } catch {
      return DEFAULT_PREFERENCES;
    }
  }

  savePreferences(prefs: UserPreferences): void {
    try {
      window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(prefs));
    } catch {
      // Ignore storage write errors
    }
  }
}

export const storageService: IPhishGuardStorage = new LocalStorageRepository();

export function downloadJsonFile(data: unknown, filename: string): void {
  const jsonString = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
