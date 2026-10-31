import 'dotenv/config';
import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { simpleParser } from 'mailparser';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  buildFinalAnalysisResult,
  runDeterministicRuleEngine,
} from './src/engine/ruleEngine';
import { validateEmailInput } from './src/engine/emailParser';
import { SUPPORTED_GEMMA_MODELS } from './src/engine/config';
import {
  getConfiguredGemmaModel,
  isAiApiKeyConfigured,
  runGemmaContextualAnalysis,
} from './src/server/aiService';
import { AttachmentMetadata, EmailScanInput } from './src/types/phishguard';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Simple sliding-window rate limiter per client IP
const rateLimitStore = new Map<string, number[]>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 scans per minute per IP

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const timestamps = (rateLimitStore.get(ip) || []).filter(
    (t) => now - t < RATE_LIMIT_WINDOW_MS
  );
  if (timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    rateLimitStore.set(ip, timestamps);
    return false;
  }
  timestamps.push(now);
  rateLimitStore.set(ip, timestamps);
  return true;
}

/**
 * Enriches raw MIME / .eml input using mailparser's simpleParser on the server
 * without ever opening URLs or executing attachments.
 */
async function enrichInputWithMailparser(input: EmailScanInput): Promise<EmailScanInput> {
  if (!input.rawInput || input.rawInput.trim().length === 0) {
    return input;
  }

  try {
    const parsed = await simpleParser(input.rawInput, {
      skipHtmlToText: false,
      skipTextToHtml: true,
      skipImageLinks: true,
    });

    const enrichedAttachments: AttachmentMetadata[] = [...(input.attachments || [])];
    if (Array.isArray(parsed.attachments)) {
      for (const att of parsed.attachments) {
        const fn = att.filename || 'unnamed_attachment';
        if (!enrichedAttachments.some((a) => a.filename === fn)) {
          enrichedAttachments.push({
            filename: fn,
            contentType: att.contentType,
            sizeBytes: att.size,
          });
        }
      }
    }

    return {
      ...input,
      subject: input.subject || parsed.subject || undefined,
      from: input.from || parsed.from?.text || undefined,
      to:
        input.to ||
        (Array.isArray(parsed.to)
          ? parsed.to.map((t) => t.text).join(', ')
          : parsed.to?.text) ||
        undefined,
      replyTo: input.replyTo || parsed.replyTo?.text || undefined,
      bodyText: input.bodyText || parsed.text || undefined,
      bodyHtml:
        input.bodyHtml ||
        (typeof parsed.html === 'string' ? parsed.html : undefined),
      attachments: enrichedAttachments,
    };
  } catch {
    // If mailparser fails on a malformed MIME message, our deterministic parser handles it
    return input;
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Enforce strict JSON payload cap (250KB wrapper cap; 100KB enforced on email content)
  app.use(express.json({ limit: '250kb' }));

  // Health check endpoint (never exposes API key)
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'PhishGuard AI Security Engine',
      timestamp: new Date().toISOString(),
      aiConfigured: isAiApiKeyConfigured(),
      configuredModel: getConfiguredGemmaModel(),
      supportedModels: SUPPORTED_GEMMA_MODELS,
    });
  });

  // Main analysis endpoint
  app.post('/api/analyze', async (req: Request, res: Response) => {
    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';

    if (!checkRateLimit(clientIp)) {
      res.status(429).json({
        error: 'Rate limit exceeded. Please wait a moment before submitting another email scan.',
      });
      return;
    }

    try {
      const rawBody = (req.body || {}) as EmailScanInput;

      // 1. Validate raw input size and structure
      const validation = validateEmailInput(rawBody);
      if (!validation.valid) {
        res.status(400).json({ error: validation.error });
        return;
      }

      // 2. Enrich MIME / .eml structures via mailparser
      const enrichedInput = await enrichInputWithMailparser(rawBody);

      // 3. Run deterministic rule engine on the server
      const bundle = runDeterministicRuleEngine(enrichedInput);

      // 4. Run Gemma 4 AI analysis if enabled
      const enableAi = rawBody.enableAi !== false;
      let aiOutput = null;
      let aiModelUsed: string | null = null;
      let aiStatusMessage = 'AI contextual analysis disabled by user preference. Showing deterministic rule-based results.';

      if (enableAi) {
        const aiResult = await runGemmaContextualAnalysis({
          redactedPayload: bundle.redactedPayload,
          extractedUrls: bundle.extractedUrls,
          ruleFindings: bundle.findings,
          attachments: bundle.parsedEmail.attachments,
          preferredModel: rawBody.preferredModel,
        });
        aiOutput = aiResult.output;
        aiModelUsed = aiResult.modelUsed;
        aiStatusMessage = aiResult.statusMessage;
      }

      // 5. Compute combined risk score, confidence, and explainable verdict
      const finalAssessment = buildFinalAnalysisResult({
        bundle,
        aiOutput,
        aiModelUsed,
        aiStatusMessage,
      });

      res.json(finalAssessment);
    } catch (err) {
      const safeMessage =
        err instanceof Error
          ? err.message
          : 'An unexpected error occurred while analyzing the email.';
      res.status(400).json({ error: safeMessage });
    }
  });

  // Vite middleware for development / static serving for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
