import fs from 'node:fs/promises';
import path from 'node:path';

export interface StorageProvider {
  put(key: string, data: string | Buffer): Promise<string>;
  get(key: string): Promise<string | null>;
  delete(key: string): Promise<void>;
}

export class MemoryStorageProvider implements StorageProvider {
  private store = new Map<string, string>();

  async put(key: string, data: string | Buffer): Promise<string> {
    const val = typeof data === 'string' ? data : data.toString('utf8');
    this.store.set(key, val);
    return `memory://${key}`;
  }

  async get(key: string): Promise<string | null> {
    const normalizedKey = key.replace(/^memory:\/\//, '');
    return this.store.get(normalizedKey) ?? null;
  }

  async delete(key: string): Promise<void> {
    const normalizedKey = key.replace(/^memory:\/\//, '');
    this.store.delete(normalizedKey);
  }
}

export class FileStorageProvider implements StorageProvider {
  private baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = path.resolve(baseDir);
  }

  private resolvePath(key: string): string {
    const normalizedKey = key.replace(/^(file|storage):\/\//, '');
    return path.join(this.baseDir, normalizedKey);
  }

  async put(key: string, data: string | Buffer): Promise<string> {
    const filePath = this.resolvePath(key);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, data);
    return `storage://${key.replace(/^(file|storage):\/\//, '')}`;
  }

  async get(key: string): Promise<string | null> {
    const filePath = this.resolvePath(key);
    try {
      const buf = await fs.readFile(filePath);
      return buf.toString('utf8');
    } catch {
      return null;
    }
  }

  async delete(key: string): Promise<void> {
    const filePath = this.resolvePath(key);
    try {
      await fs.unlink(filePath);
    } catch {
      // ignore if already deleted
    }
  }
}

export function createStorageProvider(storageDir?: string): StorageProvider {
  if (storageDir) {
    return new FileStorageProvider(storageDir);
  }
  return new MemoryStorageProvider();
}
