import { test } from 'node:test';
import assert from 'node:assert';
import { EccEngine } from '../dist/engines/ecc.js';
import { ReaEngine } from '../dist/engines/rea.js';
import { DecompiledFunction, BinaryTriageResult } from '../dist/types.js';

test('ECC Security Audit catches unsafe memory copy', () => {
  const ecc = new EccEngine();
  const mockFunction: DecompiledFunction = {
    address: '0x140001050',
    name: 'vulnerable_copy',
    signature: 'void vulnerable_copy(char* input)',
    decompiledCode: 'void vulnerable_copy(char* input) { char buf[32]; strcpy(buf, input); }',
    callers: [],
    callees: [],
    localVariables: [{ name: 'buf', type: 'char[32]' }],
    comments: [],
  };

  const findings = ecc.auditSecurity([mockFunction]);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].severity, 'high');
  assert.match(findings[0].title, /Unbounded Memory Copy/);
});

test('ECC Obligation Ledger initializes with pending items', () => {
  const ecc = new EccEngine();
  const mockTriage: BinaryTriageResult = {
    filePath: 'sample.exe',
    format: 'pe',
    architecture: 'x86_64',
    bitness: 64,
    endianness: 'little',
    isStripped: false,
    packersDetected: [],
    entryPoint: '0x140001000',
    importedLibraries: ['kernel32.dll'],
    exportedSymbols: [],
    keyStrings: ['Hello World'],
  };

  const obligations = ecc.createObligationLedger(mockTriage, []);
  assert.ok(obligations.length >= 1);
  assert.strictEqual(obligations[0].status, 'pending');
});
