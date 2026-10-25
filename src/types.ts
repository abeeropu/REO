/**
 * REO (Reverse Engineering Orchestrator) Types & Contracts
 */

export type BinaryFormat =
  | 'pe'
  | 'elf'
  | 'macho'
  | 'apk'
  | 'dex'
  | 'electron'
  | 'wasm'
  | 'firmware'
  | 'unknown';

export type TargetArchitecture =
  | 'x86'
  | 'x86_64'
  | 'arm'
  | 'arm64'
  | 'mips'
  | 'riscv'
  | 'wasm'
  | 'jvm'
  | 'unknown';

export interface BinaryTriageResult {
  filePath: string;
  format: BinaryFormat;
  architecture: TargetArchitecture;
  bitness: 32 | 64;
  endianness: 'little' | 'big';
  isStripped: boolean;
  packersDetected: string[];
  entryPoint?: string;
  importedLibraries: string[];
  exportedSymbols: string[];
  keyStrings: string[];
}

export interface DecompiledFunction {
  address: string;
  name: string;
  signature: string;
  decompiledCode: string;
  callers: string[];
  callees: string[];
  localVariables: Array<{ name: string; type: string }>;
  comments: Array<{ address: string; comment: string }>;
}

export interface DynamicTraceResult {
  functionAddress: string;
  observedArguments: Array<{ index: number; rawValue: string; decodedString?: string }>;
  returnValue?: string;
  decryptedBuffers?: Array<{ address: string; length: number; dataHex: string; ascii?: string }>;
}

export interface ObligationItem {
  id: string;
  targetAddress: string;
  hypothesis: string;
  status: 'pending' | 'in_progress' | 'verified' | 'refuted';
  evidence?: string;
}

export interface ReconstructionReport {
  target: BinaryTriageResult;
  executiveSummary: string;
  architectureDiagram: string;
  decompiledFunctions: DecompiledFunction[];
  dynamicTraces: DynamicTraceResult[];
  obligations: ObligationItem[];
  reconstructedModernSource: string;
  securityFindings: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    address?: string;
    remediation: string;
  }>;
}

export interface OrchestratorOptions {
  enableDynamicTracing?: boolean;
  ghidraServerUrl?: string;
  headlessGhidra?: boolean;
  outputFormat?: 'markdown' | 'json';
  targetFunction?: string;
  timeoutSeconds?: number;
}
