import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { AlertTriangle, CheckCircle2, Github, Loader2, ShieldCheck, Upload } from 'lucide-react';
import './styles.css';

type Finding = {
  ruleId: string;
  category: string;
  severity: string;
  explanation: string;
  filePath?: string;
  lineStart?: number;
  snippet?: string;
};

type Report = {
  bundleHash: string;
  sourceType: 'file' | 'zip' | 'github_url';
  sourceRef: string | null;
  fileCount: number;
  files: Array<{ path: string; chars: number }>;
  score: number;
  verdict: 'safe' | 'warn' | 'unsafe';
  purpose: { label: string; confidence: string; signals: string[] };
  findings: Finding[];
};

function App() {
  const [mode, setMode] = useState<'file' | 'github'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const title = useMemo(() => {
    if (report?.sourceRef) return `Verification report for ${report.sourceRef}`;
    return 'AI skill verification';
  }, [report]);

  async function verify() {
    setLoading(true);
    setError('');
    setReport(null);
    try {
      let res: Response;
      if (mode === 'file') {
        if (!file) throw new Error('Choose a .md, .zip, or source file first.');
        const form = new FormData();
        form.append('file', file);
        res = await fetch('/v1/verify', { method: 'POST', body: form });
      } else {
        res = await fetch('/v1/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ githubUrl }),
        });
      }
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? 'Verification failed');
      setReport(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page">
      <section className="hero">
        <div>
          <p className="eyebrow">Open-source verifier</p>
          <h1>Check AI skills before adding them to your agent.</h1>
          <p className="lede">
            Static rules inspect prompt injection, exfiltration, secret access, risky helpers, and excessive permissions in skill bundles.
          </p>
        </div>
        <ShieldCheck className="heroIcon" />
      </section>

      <section className="tool">
        <div className="tabs">
          <button className={mode === 'file' ? 'active' : ''} onClick={() => setMode('file')}><Upload size={18} /> File / Bundle</button>
          <button className={mode === 'github' ? 'active' : ''} onClick={() => setMode('github')}><Github size={18} /> GitHub URL</button>
        </div>

        {mode === 'file' ? (
          <label className="drop">
            <input type="file" accept=".md,.mdx,.txt,.yaml,.yml,.json,.toml,.zip,.js,.ts,.py,.sh" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
            <strong>{file ? file.name : 'Drop or choose a skill file'}</strong>
            <span>.md, .zip, and common source files are supported.</span>
          </label>
        ) : (
          <input
            className="url"
            value={githubUrl}
            onChange={(event) => setGithubUrl(event.target.value)}
            placeholder="https://github.com/owner/repo/tree/main/path/to/skill"
          />
        )}

        <button className="primary" onClick={verify} disabled={loading}>
          {loading ? <Loader2 className="spin" size={18} /> : <ShieldCheck size={18} />}
          Verify
        </button>
        {error && <p className="error">{error}</p>}
      </section>

      {report && (
        <section className="report">
          <p className="eyebrow">{report.bundleHash.slice(0, 12)}</p>
          <h2>{title}</h2>
          <div className={`score ${report.verdict}`}>
            <div>
              <strong>{report.score}</strong>
              <span>out of 100</span>
            </div>
            <div>
              <h3>{report.verdict === 'safe' ? 'Safe to use' : report.verdict === 'warn' ? 'Needs review' : 'Unsafe'}</h3>
              <p>{report.findings.length} finding{report.findings.length === 1 ? '' : 's'} across {report.fileCount} processed file{report.fileCount === 1 ? '' : 's'}.</p>
            </div>
          </div>

          <div className="purpose">
            <strong>Identified purpose</strong>
            <p>{report.purpose.label} ({report.purpose.confidence} confidence)</p>
          </div>

          <div className="findings">
            {report.findings.length === 0 ? (
              <div className="empty"><CheckCircle2 /> No findings across any category.</div>
            ) : report.findings.map((finding) => (
              <article key={`${finding.ruleId}-${finding.filePath}-${finding.lineStart}`} className={`finding ${finding.severity}`}>
                <div>
                  <span>{finding.severity}</span>
                  <code>{finding.ruleId}</code>
                </div>
                <h3>{finding.explanation}</h3>
                <p>{finding.filePath}{finding.lineStart ? `:${finding.lineStart}` : ''}</p>
                {finding.snippet && <pre>{finding.snippet}</pre>}
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="checks">
        {['Prompt injection', 'Data exfiltration', 'Secret access', 'Risky helpers', 'Permissions'].map((item) => (
          <div key={item}><AlertTriangle size={18} /><span>{item}</span></div>
        ))}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
