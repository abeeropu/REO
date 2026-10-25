import { GhidraEngine } from '../engines/ghidra.js';
import { DynamicTraceResult } from '../types.js';

export class FeedbackLoopManager {
  private ghidra: GhidraEngine;

  constructor(ghidra: GhidraEngine) {
    this.ghidra = ghidra;
  }

  /**
   * Annotate Ghidra database with dynamic trace evidence discovered by REA
   */
  async syncTraceToGhidra(trace: DynamicTraceResult): Promise<{ commentsAdded: number; variablesRenamed: number }> {
    let commentsAdded = 0;
    let variablesRenamed = 0;

    // 1. Add comment for observed arguments
    if (trace.observedArguments.length > 0) {
      const summary = trace.observedArguments
        .map((a) => `arg${a.index}: ${a.rawValue}${a.decodedString ? ` ("${a.decodedString}")` : ''}`)
        .join(', ');

      const comment = `[REO Trace] Observed Runtime Call: ${summary}`;
      const success = await this.ghidra.setDecompilerComment(trace.functionAddress, comment);
      if (success) commentsAdded++;
    }

    // 2. Add comments and renames for decrypted buffers
    if (trace.decryptedBuffers && trace.decryptedBuffers.length > 0) {
      for (const buf of trace.decryptedBuffers) {
        const comment = `[REO Decrypted Buffer] len=${buf.length} ascii="${buf.ascii || ''}"`;
        const success = await this.ghidra.setDecompilerComment(buf.address, comment);
        if (success) commentsAdded++;
      }
    }

    return { commentsAdded, variablesRenamed };
  }
}
