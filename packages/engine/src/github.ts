import { isSource, type RawSourceFile } from './bundle';

type GithubRepoRef = {
  owner: string;
  repo: string;
  kind?: 'blob' | 'tree';
  branch?: string;
  path?: string;
};

type GithubTreeItem = {
  path: string;
  type: 'blob' | 'tree' | string;
  size?: number;
};

const MAX_GITHUB_FILES = 50;
const MAX_GITHUB_FILE_BYTES = 1024 * 1024;
const MAX_GITHUB_TOTAL_BYTES = 5 * 1024 * 1024;

export async function resolveGithubUrl(githubUrl: string): Promise<RawSourceFile[]> {
  const raw = parseRawGithubUrl(githubUrl);
  if (raw) return [{ path: raw.path, bytes: await fetchBytes(raw.rawUrl) }];

  const ref = parseGithubUrl(githubUrl);
  if (!ref) throw new Error('unsupported_github_url');

  if (ref.kind === 'blob' && ref.path) {
    const branch = ref.branch ?? await fetchDefaultBranch(ref);
    return [{ path: ref.path, bytes: await fetchBytes(rawContentUrl(ref.owner, ref.repo, branch, ref.path)) }];
  }

  const branch = ref.branch ?? await fetchDefaultBranch(ref);
  const tree = await fetchRepoTree(ref, branch);
  if (ref.kind === 'tree' && typeof ref.path === 'string') {
    return fetchTreePathFiles({ owner: ref.owner, repo: ref.repo, path: ref.path }, branch, tree);
  }

  const skillDirs = new Set(
    tree
      .filter((item) => item.type === 'blob' && item.path.toLowerCase().endsWith('skill.md'))
      .map((item) => dirname(item.path)),
  );
  if (skillDirs.size === 0) throw new Error('github_skill_not_found');

  const selected = tree
    .filter((item) => item.type === 'blob')
    .filter((item) => isSource(item.path))
    .filter((item) => isInAnyDir(item.path, skillDirs))
    .filter((item) => (item.size ?? 0) <= MAX_GITHUB_FILE_BYTES)
    .slice(0, MAX_GITHUB_FILES);

  return fetchSelectedFiles(ref.owner, ref.repo, branch, selected);
}

async function fetchTreePathFiles(
  ref: Pick<GithubRepoRef, 'owner' | 'repo'> & { path: string },
  branch: string,
  tree: GithubTreeItem[],
): Promise<RawSourceFile[]> {
  const prefix = ref.path.replace(/^\/+|\/+$/g, '');
  const selected = tree
    .filter((item) => item.type === 'blob')
    .filter((item) => item.path === prefix || item.path.startsWith(`${prefix}/`))
    .filter((item) => isSource(item.path))
    .filter((item) => (item.size ?? 0) <= MAX_GITHUB_FILE_BYTES)
    .slice(0, MAX_GITHUB_FILES);
  if (selected.length === 0) throw new Error('github_no_source_files_in_tree');
  return fetchSelectedFiles(ref.owner, ref.repo, branch, selected);
}

async function fetchSelectedFiles(owner: string, repo: string, branch: string, selected: GithubTreeItem[]): Promise<RawSourceFile[]> {
  const files: RawSourceFile[] = [];
  let total = 0;
  for (const item of selected) {
    const bytes = await fetchBytes(rawContentUrl(owner, repo, branch, item.path));
    total += bytes.byteLength;
    if (total > MAX_GITHUB_TOTAL_BYTES) throw new Error('github_bundle_too_large');
    files.push({ path: item.path, bytes });
  }
  return files;
}

function parseGithubUrl(url: string): GithubRepoRef | null {
  const u = new URL(url);
  if (u.hostname !== 'github.com') return null;
  const [owner, repo, kind, branch, ...pathParts] = u.pathname.split('/').filter(Boolean);
  if (!owner || !repo) return null;
  if (kind === 'blob' || kind === 'tree') return { owner, repo, kind, branch, path: pathParts.join('/') || undefined };
  return { owner, repo };
}

function parseRawGithubUrl(url: string): { path: string; rawUrl: string } | null {
  const u = new URL(url);
  if (u.hostname !== 'raw.githubusercontent.com') return null;
  const [owner, repo, branch, ...pathParts] = u.pathname.split('/').filter(Boolean);
  if (!owner || !repo || !branch || pathParts.length === 0) return null;
  return { path: pathParts.join('/'), rawUrl: url };
}

async function fetchDefaultBranch(ref: Pick<GithubRepoRef, 'owner' | 'repo'>): Promise<string> {
  const res = await fetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, githubHeaders());
  if (!res.ok) throw new Error(`github_repo_fetch_failed:${res.status}`);
  const repo = await res.json() as { default_branch?: string };
  if (!repo.default_branch) throw new Error('github_default_branch_missing');
  return repo.default_branch;
}

async function fetchRepoTree(ref: Pick<GithubRepoRef, 'owner' | 'repo'>, branch: string): Promise<GithubTreeItem[]> {
  const res = await fetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    githubHeaders(),
  );
  if (!res.ok) throw new Error(`github_tree_fetch_failed:${res.status}`);
  const body = await res.json() as { tree?: GithubTreeItem[]; truncated?: boolean };
  if (body.truncated) throw new Error('github_tree_too_large');
  return body.tree ?? [];
}

async function fetchBytes(url: string): Promise<Uint8Array> {
  const res = await fetch(url, githubHeaders());
  if (!res.ok) throw new Error(`github_file_fetch_failed:${res.status}`);
  const len = Number(res.headers.get('content-length') ?? '0');
  if (len > MAX_GITHUB_FILE_BYTES) throw new Error('github_file_too_large');
  return new Uint8Array(await res.arrayBuffer());
}

function rawContentUrl(owner: string, repo: string, branch: string, path: string): string {
  return `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`;
}

function githubHeaders(): RequestInit {
  return {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'ai-skills-verification',
    },
  };
}

function dirname(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

function isInAnyDir(path: string, dirs: Set<string>): boolean {
  for (const dir of dirs) {
    if (dir === '') return true;
    if (path === dir || path.startsWith(`${dir}/`)) return true;
  }
  return false;
}
