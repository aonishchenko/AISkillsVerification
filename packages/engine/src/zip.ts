import { isSource, type RawSourceFile } from './bundle';

const ZIP_EOCD = 0x06054b50;
const ZIP_CENTRAL_FILE = 0x02014b50;
const ZIP_LOCAL_FILE = 0x04034b50;
const ZIP64_SENTINEL = 0xffffffff;
const MAX_ZIP_FILES = 100;

export async function readZipSourceFiles(bytes: Uint8Array, maxTotalBytes: number): Promise<RawSourceFile[]> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocdOffset = findEndOfCentralDirectory(view);
  if (eocdOffset < 0) throw new Error('zip_invalid');

  const centralDirectorySize = u32(view, eocdOffset + 12);
  const centralDirectoryOffset = u32(view, eocdOffset + 16);
  if (centralDirectorySize === ZIP64_SENTINEL || centralDirectoryOffset === ZIP64_SENTINEL) {
    throw new Error('zip64_not_supported');
  }
  if (centralDirectoryOffset + centralDirectorySize > bytes.byteLength) {
    throw new Error('zip_invalid_central_directory');
  }

  const files: RawSourceFile[] = [];
  let total = 0;
  let pos = centralDirectoryOffset;

  while (pos < centralDirectoryOffset + centralDirectorySize) {
    if (u32(view, pos) !== ZIP_CENTRAL_FILE) throw new Error('zip_invalid_central_directory');

    const flags = u16(view, pos + 8);
    const method = u16(view, pos + 10);
    const compressedSize = u32(view, pos + 20);
    const uncompressedSize = u32(view, pos + 24);
    const filenameLength = u16(view, pos + 28);
    const extraLength = u16(view, pos + 30);
    const commentLength = u16(view, pos + 32);
    const localHeaderOffset = u32(view, pos + 42);
    const rawName = bytes.subarray(pos + 46, pos + 46 + filenameLength);
    const path = sanitizeZipPath(new TextDecoder('utf-8', { fatal: false }).decode(rawName));

    pos += 46 + filenameLength + extraLength + commentLength;

    if (!path || path.endsWith('/') || shouldSkipZipPath(path) || !isSource(path)) continue;
    if ((flags & 1) === 1) throw new Error(`zip_encrypted_entry:${path}`);
    if (compressedSize === ZIP64_SENTINEL || uncompressedSize === ZIP64_SENTINEL) {
      throw new Error(`zip64_entry_not_supported:${path}`);
    }
    if (files.length >= MAX_ZIP_FILES) throw new Error('zip_too_many_source_files');
    if (total + uncompressedSize > maxTotalBytes) throw new Error('zip_uncompressed_too_large');
    if (localHeaderOffset + 30 > bytes.byteLength) throw new Error(`zip_invalid_entry:${path}`);
    if (u32(view, localHeaderOffset) !== ZIP_LOCAL_FILE) throw new Error(`zip_invalid_entry:${path}`);

    const localNameLength = u16(view, localHeaderOffset + 26);
    const localExtraLength = u16(view, localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > bytes.byteLength) throw new Error(`zip_invalid_entry:${path}`);

    const compressed = bytes.subarray(dataStart, dataEnd);
    const entryBytes = method === 0
      ? compressed
      : method === 8
        ? await inflateRaw(compressed)
        : null;
    if (!entryBytes) throw new Error(`zip_unsupported_compression:${method}:${path}`);
    if (entryBytes.byteLength !== uncompressedSize) throw new Error(`zip_size_mismatch:${path}`);

    total += entryBytes.byteLength;
    files.push({ path, bytes: entryBytes });
  }

  return files;
}

function findEndOfCentralDirectory(view: DataView): number {
  const min = Math.max(0, view.byteLength - 0xffff - 22);
  for (let pos = view.byteLength - 22; pos >= min; pos--) {
    if (u32(view, pos) === ZIP_EOCD) return pos;
  }
  return -1;
}

function sanitizeZipPath(path: string): string | null {
  const normalized = path.replace(/\\/g, '/').replace(/^\/+/, '').normalize('NFC');
  const parts = normalized.split('/');
  if (
    parts.length === 0 ||
    parts.some((part) => part === '' || part === '.' || part === '..') ||
    /^[a-zA-Z]:/.test(parts[0] ?? '')
  ) {
    return null;
  }
  return parts.join('/');
}

function shouldSkipZipPath(path: string): boolean {
  return path.startsWith('__MACOSX/') || path.endsWith('/.DS_Store') || path === '.DS_Store';
}

async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function u16(view: DataView, offset: number): number {
  return view.getUint16(offset, true);
}

function u32(view: DataView, offset: number): number {
  return view.getUint32(offset, true);
}
