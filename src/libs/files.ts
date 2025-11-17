import { readFile } from "fs/promises";

export class FileManager {
  private data?: Buffer;
  async openFile(path: string) {
    try {
      this.data = await readFile(path);
      return this;
    } catch (err) {
      throw err;
    }
  }

  async toString(encoding: BufferEncoding) {
    if (!this.data)
      throw new Error("File data is not loaded. Please call openFile() first.");
    return this.data.toString(encoding);
  }

  getFile() {
    return this.data;
  }
}
