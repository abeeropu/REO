import { DecompiledFunction } from '../types.js';

export interface GhidraEngineConfig {
  serverUrl: string;
  installDir?: string;
  headless?: boolean;
}

export class GhidraEngine {
  private serverUrl: string;
  private installDir: string;

  constructor(config?: Partial<GhidraEngineConfig>) {
    this.serverUrl = config?.serverUrl || process.env.GHIDRA_SERVER_URL || 'http://127.0.0.1:8080';
    this.installDir = config?.installDir || process.env.GHIDRA_INSTALL_DIR || 'D:\\tools\\ghidra_12.2_PUBLIC';
  }

  /**
   * Check if the GhidraMCP backend is running (e.g. inside Ghidra GUI)
   */
  async isServerRunning(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${this.serverUrl}/get_program_info`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get information on current program loaded in Ghidra
   */
  async getProgramInfo(): Promise<any> {
    const res = await this.callRpc('get_program_info', {});
    return res;
  }

  /**
   * Decompile a function by hex address (e.g. "0x140001000")
   */
  async decompileFunction(address: string): Promise<DecompiledFunction> {
    const data = await this.callRpc('decompile_function_by_address', { address });
    const calls = await this.getFunctionCalls(address).catch(() => ({ callees: [] }));
    const xrefs = await this.getFunctionXrefs(address).catch(() => ({ callers: [] }));

    return {
      address,
      name: data?.name || `sub_${address.replace('0x', '')}`,
      signature: data?.signature || `void ${data?.name || 'sub'}(void)`,
      decompiledCode: data?.decompilation || data?.code || '// Decompilation unavailable',
      callers: xrefs?.callers || [],
      callees: calls?.callees || [],
      localVariables: data?.variables || [],
      comments: data?.comments || [],
    };
  }

  /**
   * List all functions in current program
   */
  async listFunctions(offset = 0, limit = 50): Promise<any> {
    return this.callRpc('list_functions', { offset, limit });
  }

  /**
   * Search functions by name pattern
   */
  async searchFunctions(query: string): Promise<any> {
    return this.callRpc('search_functions_by_name', { query });
  }

  /**
   * Get callers and xrefs to a function
   */
  async getFunctionXrefs(address: string): Promise<{ callers: string[] }> {
    const res = await this.callRpc('get_function_xrefs', { address });
    return {
      callers: Array.isArray(res?.xrefs) ? res.xrefs.map((x: any) => x.from || x.address || String(x)) : [],
    };
  }

  /**
   * Get outbound calls from a function
   */
  async getFunctionCalls(address: string): Promise<{ callees: string[] }> {
    const res = await this.callRpc('get_function_calls', { address });
    return {
      callees: Array.isArray(res?.calls) ? res.calls.map((c: any) => c.to || c.target || String(c)) : [],
    };
  }

  /**
   * Read raw memory bytes from Ghidra database
   */
  async readMemory(address: string, length: number): Promise<string> {
    const res = await this.callRpc('read_memory', { address, length });
    return res?.bytes_hex || res?.data || '';
  }

  /**
   * Mutation: Rename a function in Ghidra database
   */
  async renameFunction(address: string, newName: string): Promise<boolean> {
    try {
      await this.callRpc('rename_function_by_address', { address, new_name: newName });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Mutation: Rename a local variable in Ghidra
   */
  async renameVariable(functionAddress: string, oldName: string, newName: string): Promise<boolean> {
    try {
      await this.callRpc('rename_variable', {
        function_address: functionAddress,
        old_name: oldName,
        new_name: newName,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Mutation: Set function prototype (types, arguments, return type)
   */
  async setPrototype(functionAddress: string, prototype: string): Promise<boolean> {
    try {
      await this.callRpc('set_function_prototype', {
        function_address: functionAddress,
        prototype,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Mutation: Add inline comment in Ghidra decompiler
   */
  async setDecompilerComment(address: string, comment: string): Promise<boolean> {
    try {
      await this.callRpc('set_decompiler_comment', { address, comment });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Internal helper to send JSON-RPC / HTTP POST to Ghidra backend
   */
  private async callRpc(method: string, params: Record<string, any>): Promise<any> {
    const endpoint = `${this.serverUrl}/${method}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Ghidra server responded with status ${response.status}`);
      }

      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
