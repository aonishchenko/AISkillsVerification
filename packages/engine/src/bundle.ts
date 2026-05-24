export interface RawSourceFile {
  path: string;
  bytes: Uint8Array;
}

export interface NormalizedFile {
  path: string;
  text: string;
}

const SOURCE_EXT = new Set([
  '.md', '.mdx', '.txt', '.yml', '.yaml', '.json', '.toml',
  '.py', '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs',
  '.sh', '.bash', '.zsh', '.rb', '.go', '.rs',
]);

export function isSource(path: string): boolean {
  const i = path.lastIndexOf('.');
  const ext = i < 0 ? '' : path.slice(i).toLowerCase();
  return SOURCE_EXT.has(ext);
}

export async function normalize(files: RawSourceFile[]): Promise<{ files: NormalizedFile[]; bundleHash: string }> {
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const normalized: NormalizedFile[] = [];

  for (const file of files) {
    if (!isSource(file.path)) continue;
    let text = decoder.decode(file.bytes);
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    normalized.push({ path: file.path.normalize('NFC'), text });
  }

  normalized.sort((a, b) => a.path.localeCompare(b.path));

  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const file of normalized) {
    parts.push(encoder.encode(file.path));
    parts.push(new Uint8Array([0]));
    parts.push(encoder.encode(file.text));
    parts.push(new Uint8Array([0]));
  }

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    merged.set(part, offset);
    offset += part.length;
  }

  const digest = await crypto.subtle.digest('SHA-256', merged);
  const bundleHash = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  return { files: normalized, bundleHash };
}
