import { AnalysisResult, EmailScanInput } from '../types/phishguard';
import {
  buildFinalAnalysisResult,
  runDeterministicRuleEngine,
} from '../engine/ruleEngine';

export interface HealthStatus {
  status: string;
  aiConfigured: boolean;
  configuredModel: string;
  supportedModels: string[];
}

export async function fetchServerHealth(): Promise<HealthStatus> {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error('Health endpoint returned non-200');
    return await res.json();
  } catch {
    return {
      status: 'degraded',
      aiConfigured: false,
      configuredModel: 'gemma-4-31b-it',
      supportedModels: ['gemma-4-31b-it', 'gemma-4-26b-a4b-it'],
    };
  }
}

export async function analyzeEmailRequest(
  input: EmailScanInput
): Promise<AnalysisResult> {
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(input),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || `Analysis request failed (HTTP ${response.status})`);
    }

    return data as AnalysisResult;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // If it was an input validation error (400), rethrow so the user sees the validation message
    if (
      message.includes('cannot be empty') ||
      message.includes('100 KB') ||
      message.includes('Unsupported file format') ||
      message.includes('0 bytes')
    ) {
      throw err;
    }

    // If backend network failed, fall back to deterministic local rule engine
    const bundle = runDeterministicRuleEngine(input);
    return buildFinalAnalysisResult({
      bundle,
      aiOutput: null,
      aiModelUsed: null,
      aiStatusMessage: `Backend AI service unreachable (${message}). Completed full local deterministic rule analysis.`,
    });
  }
}
