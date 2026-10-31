import { z } from 'zod';
import { AIAnalysisOutput } from '../types/phishguard';

function stripExecutableMarkup(str: string): string {
  return str
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')
    .trim();
}

const TacticSchema = z.object({
  tactic: z.string().transform(stripExecutableMarkup),
  evidence: z.string().transform(stripExecutableMarkup),
  explanation: z.string().transform(stripExecutableMarkup),
  severity: z.enum(['low', 'medium', 'high']).catch('medium'),
});

export const AIAnalysisSchema = z.object({
  classification: z.enum(['safe', 'suspicious', 'likely_phishing']),
  confidence: z.number().min(0).max(100).transform((n) => Math.round(n)),
  risk_score: z.number().min(0).max(100).transform((n) => Math.round(n)),
  summary: z.string().min(1).transform(stripExecutableMarkup),
  social_engineering_tactics: z.array(TacticSchema).default([]),
  impersonation_indicators: z.array(z.string().transform(stripExecutableMarkup)).default([]),
  contextual_red_flags: z.array(z.string().transform(stripExecutableMarkup)).default([]),
  credential_requests: z.array(z.string().transform(stripExecutableMarkup)).default([]),
  financial_requests: z.array(z.string().transform(stripExecutableMarkup)).default([]),
  recommendations: z.array(z.string().transform(stripExecutableMarkup)).default([]),
  limitations: z.array(z.string().transform(stripExecutableMarkup)).default([]),
});

/**
 * Attempts controlled JSON extraction and validation against AIAnalysisSchema.
 */
export function parseAndValidateAiJson(rawText: string): {
  valid: boolean;
  data?: AIAnalysisOutput;
  error?: string;
} {
  if (!rawText || typeof rawText !== 'string') {
    return { valid: false, error: 'Empty AI response text.' };
  }

  let candidate = rawText.trim();

  // Strip markdown code blocks if present
  const codeBlockMatch = candidate.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (codeBlockMatch) {
    candidate = codeBlockMatch[1].trim();
  } else {
    // Extract first { to last }
    const firstBrace = candidate.indexOf('{');
    const lastBrace = candidate.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      candidate = candidate.slice(firstBrace, lastBrace + 1);
    }
  }

  let parsedObj: unknown;
  try {
    parsedObj = JSON.parse(candidate);
  } catch {
    // Controlled repair attempt: remove trailing commas before } or ]
    try {
      const repaired = candidate.replace(/,\s*([}\]])/g, '$1');
      parsedObj = JSON.parse(repaired);
    } catch (err) {
      return {
        valid: false,
        error: `Invalid JSON syntax from AI model: ${err instanceof Error ? err.message : 'parse error'}`,
      };
    }
  }

  const result = AIAnalysisSchema.safeParse(parsedObj);
  if (!result.success) {
    return {
      valid: false,
      error: `AI response failed schema validation: ${result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    };
  }

  return {
    valid: true,
    data: result.data,
  };
}
