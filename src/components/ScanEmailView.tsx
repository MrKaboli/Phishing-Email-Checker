import React, { useState, useEffect, useRef } from 'react';
import {
  Upload,
  FileText,
  Trash2,
  Shield,
  AlertCircle,
  CheckCircle2,
  Loader2,
  SlidersHorizontal,
  Info,
  EyeOff,
  Cpu,
} from 'lucide-react';
import {
  AttachmentMetadata,
  EmailScanInput,
  UserPreferences,
} from '../types/phishguard';
import { MAX_EMAIL_SIZE_BYTES, ADVISORY_DISCLAIMER } from '../engine/config';
import { SAMPLE_EMAIL_FIXTURES, SampleEmailFixture } from '../engine/sampleEmails';

interface ScanEmailViewProps {
  preferences: UserPreferences;
  onUpdatePreferences: (prefs: UserPreferences) => void;
  onRunScan: (input: EmailScanInput) => Promise<void>;
  initialSampleId?: string | null;
  onClearInitialSample?: () => void;
}

const LOADING_STAGES = [
  '1. Parsing email.',
  '2. Extracting indicators.',
  '3. Running security rules.',
  '4. Performing AI analysis.',
  '5. Calculating final risk assessment.',
];

export const ScanEmailView: React.FC<ScanEmailViewProps> = ({
  preferences,
  onUpdatePreferences,
  onRunScan,
  initialSampleId,
  onClearInitialSample,
}) => {
  const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste');
  const [showStructuredFields, setShowStructuredFields] = useState(false);

  // Paste fields
  const [rawEmailText, setRawEmailText] = useState('');
  const [subject, setSubject] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [rawHeaders, setRawHeaders] = useState('');
  const [attachmentNamesInput, setAttachmentNamesInput] = useState('');

  // Upload fields
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [uploadedFileSize, setUploadedFileSize] = useState<number | null>(null);
  const [uploadedFileContent, setUploadedFileContent] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Error & Loading state
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeStageIdx, setActiveStageIdx] = useState(0);

  const applySampleFixture = (fixture: SampleEmailFixture) => {
    setValidationError(null);
    setInputMode('paste');
    setUploadedFileName(null);
    setUploadedFileSize(null);
    setUploadedFileContent('');

    const inp = fixture.input;
    if (inp.rawInput) {
      setRawEmailText(inp.rawInput);
      setSubject(inp.subject || '');
      setFrom(inp.from || '');
      setTo(inp.to || '');
      setReplyTo(inp.replyTo || '');
      setRawHeaders(inp.rawHeaders || '');
      const attNames = (inp.attachments || []).map((a) => a.filename).join(', ');
      setAttachmentNamesInput(attNames);
      setShowStructuredFields(Boolean(attNames));
    } else {
      setRawEmailText(inp.bodyHtml || inp.bodyText || '');
      setSubject(inp.subject || '');
      setFrom(inp.from || '');
      setTo(inp.to || '');
      setReplyTo(inp.replyTo || '');
      setRawHeaders(inp.rawHeaders || '');
      const attNames = (inp.attachments || []).map((a) => a.filename).join(', ');
      setAttachmentNamesInput(attNames);
      setShowStructuredFields(true);
    }
  };

  useEffect(() => {
    if (initialSampleId) {
      const found = SAMPLE_EMAIL_FIXTURES.find((f) => f.id === initialSampleId);
      if (found) {
        applySampleFixture(found);
      }
      if (onClearInitialSample) {
        onClearInitialSample();
      }
    }
  }, [initialSampleId, onClearInitialSample]);

  const handleFileChange = async (file: File | null) => {
    setValidationError(null);
    if (!file) return;

    const lowerName = file.name.toLowerCase();
    if (!lowerName.endsWith('.eml') && !lowerName.endsWith('.txt')) {
      setValidationError(
        `Invalid file extension for "${file.name}". Only .eml and .txt files are supported.`
      );
      return;
    }

    if (file.size === 0) {
      setValidationError(`The uploaded file "${file.name}" is empty (0 bytes).`);
      return;
    }

    if (file.size > MAX_EMAIL_SIZE_BYTES) {
      setValidationError(
        `File "${file.name}" (${(file.size / 1024).toFixed(1)} KB) exceeds the maximum allowed size of 100 KB.`
      );
      return;
    }

    try {
      const text = await file.text();
      if (!text.trim()) {
        setValidationError(`The file "${file.name}" contains only whitespace.`);
        return;
      }
      setUploadedFileName(file.name);
      setUploadedFileSize(file.size);
      setUploadedFileContent(text);
    } catch {
      setValidationError('Unable to read the selected file. Please verify file encoding.');
    }
  };

  const handleRemoveUploadedFile = () => {
    setUploadedFileName(null);
    setUploadedFileSize(null);
    setUploadedFileContent('');
    setValidationError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClearPasteForm = () => {
    setRawEmailText('');
    setSubject('');
    setFrom('');
    setTo('');
    setReplyTo('');
    setRawHeaders('');
    setAttachmentNamesInput('');
    setValidationError(null);
  };

  const handleSubmitAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isAnalyzing) return;

    setValidationError(null);

    const parsedAttachments: AttachmentMetadata[] = attachmentNamesInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((filename) => ({ filename }));

    const scanInput: EmailScanInput =
      inputMode === 'upload'
        ? {
            rawInput: uploadedFileContent,
            uploadedFileName: uploadedFileName || undefined,
            uploadedFileSize: uploadedFileSize ?? undefined,
            enableAi: preferences.aiAnalysisEnabled,
            redactPii: preferences.redactPiiBeforeAi,
            preferredModel: preferences.preferredGemmaModel,
          }
        : {
            rawInput: rawEmailText,
            subject: subject.trim() || undefined,
            from: from.trim() || undefined,
            to: to.trim() || undefined,
            replyTo: replyTo.trim() || undefined,
            rawHeaders: rawHeaders.trim() || undefined,
            attachments: parsedAttachments.length > 0 ? parsedAttachments : undefined,
            enableAi: preferences.aiAnalysisEnabled,
            redactPii: preferences.redactPiiBeforeAi,
            preferredModel: preferences.preferredGemmaModel,
          };

    // Quick client pre-check
    if (inputMode === 'upload' && !uploadedFileName) {
      setValidationError('Please select a valid .eml or .txt email file before analyzing.');
      return;
    }

    const totalContent = [
      scanInput.rawInput || '',
      scanInput.subject || '',
      scanInput.from || '',
      scanInput.rawHeaders || '',
    ]
      .join('\n')
      .trim();

    if (!totalContent && (!scanInput.attachments || scanInput.attachments.length === 0)) {
      setValidationError(
        'Email content cannot be empty. Paste an email or select a sample preset above.'
      );
      return;
    }

    const byteCount = new TextEncoder().encode(totalContent).length;
    if (byteCount > MAX_EMAIL_SIZE_BYTES) {
      setValidationError(
        `Email content (${(byteCount / 1024).toFixed(1)} KB) exceeds the 100 KB security limit.`
      );
      return;
    }

    setIsAnalyzing(true);
    setActiveStageIdx(0);

    // Progress through loading stages cleanly
    const stageInterval = window.setInterval(() => {
      setActiveStageIdx((prev) => (prev < LOADING_STAGES.length - 1 ? prev + 1 : prev));
    }, 280);

    try {
      // Ensure the user sees the structured loading stages briefly even when local rules finish in <10ms
      const minStepPromise = new Promise((resolve) => setTimeout(resolve, 650));
      const [_, __] = await Promise.all([onRunScan(scanInput), minStepPromise]);
    } catch (err) {
      setValidationError(
        err instanceof Error ? err.message : 'Failed to analyze email.'
      );
    } finally {
      window.clearInterval(stageInterval);
      setIsAnalyzing(false);
    }
  };

  const currentByteSize = new TextEncoder().encode(
    inputMode === 'upload'
      ? uploadedFileContent
      : [rawEmailText, subject, from, to, replyTo, rawHeaders].join('\n')
  ).length;

  return (
    <div className="space-y-6">
      {/* Header & Header Accuracy Notice */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
              Scan Email for Threats
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Inspect raw MIME messages, headers, links, sender authentication,
              and social engineering indicators without executing remote content.
            </p>
          </div>

          {/* Input Mode Segmented Control */}
          <div
            className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start sm:self-auto"
            role="tablist"
            aria-label="Email Input Method"
          >
            <button
              type="button"
              role="tab"
              aria-selected={inputMode === 'paste'}
              onClick={() => {
                setInputMode('paste');
                setValidationError(null);
              }}
              className={`px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                inputMode === 'paste'
                  ? 'bg-cyan-500 text-slate-950'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              Paste Email
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={inputMode === 'upload'}
              onClick={() => {
                setInputMode('upload');
                setValidationError(null);
              }}
              className={`px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                inputMode === 'upload'
                  ? 'bg-cyan-500 text-slate-950'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              Upload .eml / .txt File
            </button>
          </div>
        </div>

        {/* Required Notice */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg px-4 py-3 flex items-center gap-3 text-xs sm:text-sm text-slate-300">
          <Info className="w-4 h-4 text-cyan-400 shrink-0" aria-hidden="true" />
          <span>
            Full email headers improve detection accuracy. You can still scan an
            email without them.
          </span>
        </div>
      </div>

      {/* Quick Sample Presets Bar */}
      <section
        aria-label="Sample Email Test Fixtures"
        className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3"
      >
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-semibold text-slate-300">
            Load Realistic Test Email Preset
          </span>
          <span className="text-xs text-slate-400">
            Click any preset to populate the scanner
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {SAMPLE_EMAIL_FIXTURES.slice(0, 8).map((sample) => (
            <button
              key={sample.id}
              type="button"
              onClick={() => applySampleFixture(sample)}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-slate-800 hover:border-slate-700 text-slate-200 transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <span
                className={
                  sample.category === 'legitimate'
                    ? 'text-emerald-400 font-semibold'
                    : 'text-red-400 font-semibold'
                }
              >
                {sample.category === 'legitimate' ? '[Legit]' : '[Threat]'}
              </span>
              <span>{sample.title}</span>
            </button>
          ))}
        </div>
      </section>

      {/* Main Scan Form */}
      <form onSubmit={handleSubmitAnalyze} className="space-y-6">
        {validationError && (
          <div
            role="alert"
            className="bg-red-950/60 border border-red-500/40 rounded-xl p-4 flex items-start gap-3 text-red-200 text-sm"
          >
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="space-y-1">
              <div className="font-semibold text-red-300">Validation Error</div>
              <div>{validationError}</div>
            </div>
          </div>
        )}

        {inputMode === 'paste' ? (
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <label
                  htmlFor="raw-email-editor"
                  className="block text-sm font-semibold text-slate-200"
                >
                  Email Content (Raw MIME Email or Body Text)
                </label>
                <p className="text-xs text-slate-400 mt-0.5">
                  Paste the complete raw email (including From, Reply-To,
                  Authentication-Results, and body) or just the message text.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowStructuredFields((prev) => !prev)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-slate-200 transition-colors cursor-pointer"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                  <span>
                    {showStructuredFields
                      ? 'Hide Optional Metadata Fields'
                      : 'Add Separate Subject / Sender / Attachment Fields'}
                  </span>
                </button>
                {rawEmailText && (
                  <button
                    type="button"
                    onClick={handleClearPasteForm}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Clear</span>
                  </button>
                )}
              </div>
            </div>

            {showStructuredFields && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 bg-slate-900/70 border border-slate-800 rounded-lg">
                <div>
                  <label
                    htmlFor="email-subject-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    Email Subject (Optional)
                  </label>
                  <input
                    id="email-subject-input"
                    type="text"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="e.g. URGENT: Verify your account within 24 hours"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label
                    htmlFor="email-from-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    Sender / From (Optional)
                  </label>
                  <input
                    id="email-from-input"
                    type="text"
                    value={from}
                    onChange={(e) => setFrom(e.target.value)}
                    placeholder='e.g. "PayPal Support" <service@paypa1.com>'
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label
                    htmlFor="email-to-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    Recipient / To (Optional)
                  </label>
                  <input
                    id="email-to-input"
                    type="text"
                    value={to}
                    onChange={(e) => setTo(e.target.value)}
                    placeholder="e.g. employee@company.com"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label
                    htmlFor="email-attachments-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    Attachment Filenames (Comma-separated, Optional)
                  </label>
                  <input
                    id="email-attachments-input"
                    type="text"
                    value={attachmentNamesInput}
                    onChange={(e) => setAttachmentNamesInput(e.target.value)}
                    placeholder="e.g. invoice.pdf.exe, statement.zip"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>
            )}

            <div>
              <textarea
                id="raw-email-editor"
                rows={9}
                value={rawEmailText}
                onChange={(e) => setRawEmailText(e.target.value)}
                placeholder={`Paste raw email headers + body or plain email text here...\n\nExample:\nFrom: "PayPal Billing" <service@paypa1.com>\nSubject: Urgent Account Verification Required\nAuthentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\n\nDear Customer, your account will be suspended within 24 hours. Please verify your password at https://www.paypa1.com/login`}
                className="w-full p-4 text-sm font-mono bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed resize-y"
              />
              <div className="mt-2 flex items-center justify-between text-xs text-slate-400 font-mono tabular-nums">
                <span>Safe offline parsing: Links and HTML are never rendered or fetched</span>
                <span
                  className={
                    currentByteSize > MAX_EMAIL_SIZE_BYTES
                      ? 'text-red-400 font-semibold'
                      : 'text-slate-400'
                  }
                >
                  {(currentByteSize / 1024).toFixed(2)} KB / 100.00 KB max
                </span>
              </div>
            </div>
          </div>
        ) : (
          /* Option B: Upload .eml or .txt file */
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-5">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                Upload Raw Email File (.eml or .txt)
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Maximum file size: 100 KB. Files are parsed safely without
                opening external links or attachments.
              </p>
            </div>

            {!uploadedFileName ? (
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  const file = e.dataTransfer.files?.[0] || null;
                  handleFileChange(file);
                }}
                className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 bg-slate-950/60 rounded-xl p-8 text-center transition-colors"
              >
                <Upload
                  className="w-8 h-8 text-cyan-400 mx-auto mb-3"
                  aria-hidden="true"
                />
                <p className="text-sm font-medium text-slate-200">
                  Drag and drop your <code className="font-mono">.eml</code> or{' '}
                  <code className="font-mono">.txt</code> file here
                </p>
                <p className="text-xs text-slate-400 mt-1 mb-4">
                  UTF-8, Quoted-Printable, and MIME multipart messages supported (up to 100 KB)
                </p>
                <label
                  htmlFor="email-file-upload"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 rounded-lg text-xs font-semibold cursor-pointer transition-colors"
                >
                  <FileText className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <span>Select Email File</span>
                  <input
                    ref={fileInputRef}
                    id="email-file-upload"
                    type="file"
                    accept=".eml,.txt,message/rfc822,text/plain"
                    onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
                    className="sr-only"
                  />
                </label>
              </div>
            ) : (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
                      <FileText className="w-5 h-5 text-cyan-400" aria-hidden="true" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-slate-100 truncate font-mono">
                        {uploadedFileName}
                      </div>
                      <div className="text-xs text-slate-400 font-mono tabular-nums">
                        {((uploadedFileSize || 0) / 1024).toFixed(2)} KB · Ready for inspection
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleRemoveUploadedFile}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-300 bg-red-950/50 hover:bg-red-900/60 border border-red-500/30 rounded-lg transition-colors cursor-pointer shrink-0"
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Remove / Replace File</span>
                  </button>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-48 overflow-y-auto">
                  <div className="text-xs text-slate-400 mb-1 font-medium">
                    Raw File Preview (First 800 characters):
                  </div>
                  <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
                    {uploadedFileContent.slice(0, 800)}
                    {uploadedFileContent.length > 800 ? '\n...' : ''}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Privacy & Analysis Mode Controls Bar + Prominent ANALYZE EMAIL Button */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300">
            <label className="inline-flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={preferences.aiAnalysisEnabled}
                onChange={(e) =>
                  onUpdatePreferences({
                    ...preferences,
                    aiAnalysisEnabled: e.target.checked,
                  })
                }
                className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <Cpu className="w-4 h-4 text-cyan-400" aria-hidden="true" />
              <span>
                Gemma 4 Contextual AI ({preferences.preferredGemmaModel})
              </span>
            </label>

            <label className="inline-flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={preferences.redactPiiBeforeAi}
                onChange={(e) =>
                  onUpdatePreferences({
                    ...preferences,
                    redactPiiBeforeAi: e.target.checked,
                  })
                }
                className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <EyeOff className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              <span>Redact personal information before AI analysis</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={isAnalyzing}
            className="inline-flex items-center justify-center gap-2.5 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-800 disabled:text-slate-400 text-slate-950 font-bold text-sm rounded-lg transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                <span>ANALYZING EMAIL...</span>
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" aria-hidden="true" />
                <span>ANALYZE EMAIL</span>
              </>
            )}
          </button>
        </div>

        {/* 5-Stage Progress Indicator when scanning */}
        {isAnalyzing && (
          <div
            role="status"
            aria-live="polite"
            className="bg-[#111827] border border-cyan-500/40 rounded-xl p-6 space-y-4"
          >
            <div className="flex items-center justify-between text-sm font-semibold text-cyan-300">
              <span>Executing Multi-Layer Security Inspection...</span>
              <span className="font-mono tabular-nums">
                Stage {activeStageIdx + 1} of {LOADING_STAGES.length}
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
              {LOADING_STAGES.map((stageLabel, idx) => {
                const isDone = idx < activeStageIdx;
                const isCurrent = idx === activeStageIdx;
                return (
                  <div
                    key={stageLabel}
                    className={`p-3 rounded-lg border text-xs font-medium flex items-center gap-2 ${
                      isDone
                        ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                        : isCurrent
                          ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                          : 'bg-slate-900/50 border-slate-800 text-slate-500'
                    }`}
                  >
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
                    ) : isCurrent ? (
                      <Loader2 className="w-4 h-4 text-cyan-400 animate-spin shrink-0" aria-hidden="true" />
                    ) : (
                      <span className="w-4 h-4 rounded-full border border-slate-700 shrink-0" />
                    )}
                    <span>{stageLabel}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </form>

      <div className="text-xs text-slate-400 bg-[#111827] border border-slate-800 rounded-xl p-4">
        {ADVISORY_DISCLAIMER}
      </div>
    </div>
  );
};
