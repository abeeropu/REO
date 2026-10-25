import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import { BinaryFormat, BinaryTriageResult, TargetArchitecture, DynamicTraceResult } from '../types.js';

const execFileAsync = promisify(execFile);

export class ReaEngine {
  private reaCommand: string;

  constructor(reaPath?: string) {
    this.reaCommand = reaPath || process.env.REA_CLI_PATH || 'rea';
  }

  /**
   * Sniff binary file header magic bytes to detect file format autonomously
   */
  async detectFormat(filePath: string): Promise<{ format: BinaryFormat; architecture: TargetArchitecture; bitness: 32 | 64 }> {
    const handle = await fs.open(filePath, 'r');
    const buffer = Buffer.alloc(512);
    await handle.read(buffer, 0, 512, 0);
    await handle.close();

    // PE (Windows EXE / DLL): "MZ" header + "PE\0\0"
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      const peOffset = buffer.readUInt32LE(0x3c);
      if (peOffset + 4 < buffer.length && buffer.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0') {
        const machine = buffer.readUInt16LE(peOffset + 4);
        const is64 = machine === 0x8664 || machine === 0xaa64;
        const arch: TargetArchitecture = machine === 0x8664 ? 'x86_64' : machine === 0x14c ? 'x86' : machine === 0xaa64 ? 'arm64' : 'unknown';
        return { format: 'pe', architecture: arch, bitness: is64 ? 64 : 32 };
      }
      return { format: 'pe', architecture: 'x86', bitness: 32 };
    }

    // ELF (Linux): "\x7fELF"
    if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      const is64 = buffer[4] === 2;
      const machine = buffer.readUInt16LE(0x12);
      const arch: TargetArchitecture = machine === 0x3e ? 'x86_64' : machine === 0x03 ? 'x86' : machine === 0xb7 ? 'arm64' : machine === 0x28 ? 'arm' : 'unknown';
      return { format: 'elf', architecture: arch, bitness: is64 ? 64 : 32 };
    }

    // Mach-O (macOS): 0xFEEDFACE (32) or 0xFEEDFACF (64)
    const magic = buffer.readUInt32BE(0);
    if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcafebabe) {
      return { format: 'macho', architecture: 'arm64', bitness: magic === 0xfeedfacf ? 64 : 32 };
    }

    // WebAssembly: "\0asm"
    if (buffer.readUInt32BE(0) === 0x0061736d) {
      return { format: 'wasm', architecture: 'wasm', bitness: 32 };
    }

    // Android DEX: "dex\n"
    if (buffer.toString('ascii', 0, 4) === 'dex\n') {
      return { format: 'dex', architecture: 'jvm', bitness: 32 };
    }

    // ZIP based: APK / JAR / ZIP
    if (buffer[0] === 0x50 && buffer[1] === 0x4b) {
      if (filePath.endsWith('.apk')) {
        return { format: 'apk', architecture: 'arm64', bitness: 64 };
      }
    }

    // Electron ASAR
    if (filePath.endsWith('.asar')) {
      return { format: 'electron', architecture: 'unknown', bitness: 64 };
    }

    return { format: 'unknown', architecture: 'unknown', bitness: 64 };
  }

  /**
   * Run REA triage using the rea CLI or autonomous built-in fallback
   */
  async triageBinary(filePath: string): Promise<BinaryTriageResult> {
    const { format, architecture, bitness } = await this.detectFormat(filePath);

    // Try rea CLI if installed
    try {
      const { stdout } = await execFileAsync(this.reaCommand, ['binary_overview', filePath, '--json'], {
        timeout: 10000,
      });
      const data = JSON.parse(stdout);
      return {
        filePath,
        format,
        architecture,
        bitness,
        endianness: data.endianness || 'little',
        isStripped: data.is_stripped ?? false,
        packersDetected: data.packers || [],
        entryPoint: data.entry_point || '0x140001000',
        importedLibraries: data.imports || [],
        exportedSymbols: data.exports || [],
        keyStrings: data.strings?.slice(0, 20) || [],
      };
    } catch {
      // Fallback: Autonomous rapid extraction
      const strings = await this.extractStrings(filePath, 30);
      return {
        filePath,
        format,
        architecture,
        bitness,
        endianness: 'little',
        isStripped: true,
        packersDetected: [],
        entryPoint: '0x140001000',
        importedLibraries: [],
        exportedSymbols: [],
        keyStrings: strings,
      };
    }
  }

  /**
   * Run Frida or Rizin dynamic instrumentation via REA to trace function arguments and decrypted memory
   */
  async traceFunction(filePath: string, functionAddress: string): Promise<DynamicTraceResult> {
    try {
      const { stdout } = await execFileAsync(
        this.reaCommand,
        ['instrument_with_frida', filePath, '--hook-address', functionAddress, '--json'],
        { timeout: 15000 }
      );
      const data = JSON.parse(stdout);
      return {
        functionAddress,
        observedArguments: data.args || [],
        returnValue: data.return_value,
        decryptedBuffers: data.buffers || [],
      };
    } catch {
      // Graceful fallback when dynamic environment isn't attached
      return {
        functionAddress,
        observedArguments: [],
        decryptedBuffers: [],
      };
    }
  }

  /**
   * Extract printable ASCII strings from binary
   */
  private async extractStrings(filePath: string, limit = 20): Promise<string[]> {
    try {
      const data = await fs.readFile(filePath);
      const strings: string[] = [];
      let current = '';

      for (let i = 0; i < data.length && strings.length < limit; i++) {
        const byte = data[i];
        if (byte >= 32 && byte <= 126) {
          current += String.fromCharCode(byte);
        } else {
          if (current.length >= 6) {
            strings.push(current);
          }
          current = '';
        }
      }
      return strings;
    } catch {
      return [];
    }
  }
}
