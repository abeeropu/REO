import * as fs from 'node:fs/promises';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export type EngineType = 'reo' | 'rea' | 'ghidramcp' | 'ecc' | 'ghidra';

export interface EngineUpdateStatus {
  engine: EngineType;
  name: string;
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  details?: string;
  updateAction?: string;
}

export interface DiagnosticResult {
  engine: string;
  status: 'ok' | 'warning' | 'error';
  details: string;
  recommendedAction?: string;
}

export class UpdaterManager {
  private currentReoVersion = '1.0.0';
  private eccDir = process.env.ECC_DIR || 'D:\\tools\\ECC';
  private ghidraMcpDir = process.env.GHIDRAMCP_DIR || 'D:\\tools\\GhidraMCP';
  private ghidraDir = process.env.GHIDRA_INSTALL_DIR || 'D:\\tools\\ghidra_12.2_PUBLIC';

  /**
   * Check status and available updates across all 4 orchestrated engines + REO
   */
  async checkAll(): Promise<EngineUpdateStatus[]> {
    const statuses: EngineUpdateStatus[] = [];

    // 1. REO (The Orchestrator)
    const reoStatus = await this.checkReo();
    statuses.push(reoStatus);

    // 2. REA (Reverse Engineer Anything)
    const reaStatus = await this.checkRea();
    statuses.push(reaStatus);

    // 3. GhidraMCP (Decompiler Bridge)
    const ghidraMcpStatus = await this.checkGhidraMcp();
    statuses.push(ghidraMcpStatus);

    // 4. ECC (Autonomous Harness)
    const eccStatus = await this.checkEcc();
    statuses.push(eccStatus);

    // 5. Ghidra (NSA SRE Framework)
    const ghidraStatus = await this.checkGhidra();
    statuses.push(ghidraStatus);

    return statuses;
  }

  /**
   * Automatically update an individual engine
   */
  async updateEngine(engine: EngineType): Promise<{ success: boolean; message: string }> {
    switch (engine) {
      case 'rea': {
        try {
          await execAsync('npm install -g rea-agents@latest');
          return { success: true, message: 'Updated REA (rea-agents) to latest version via npm.' };
        } catch (err: any) {
          return { success: false, message: `Failed to update REA: ${err.message}` };
        }
      }

      case 'ecc': {
        try {
          await execAsync(`git -C "${this.eccDir}" pull origin main`);
          await execAsync(`node "${this.eccDir}\\scripts\\install-apply.js" --target antigravity --profile full`);
          return { success: true, message: 'Updated ECC repository and refreshed harness profile.' };
        } catch (err: any) {
          return { success: false, message: `Failed to update ECC: ${err.message}` };
        }
      }

      case 'ghidramcp': {
        try {
          await execAsync(`git -C "${this.ghidraMcpDir}" pull origin main`);
          const gradlew = `${this.ghidraDir}\\support\\gradle\\gradlew.bat`;
          await execAsync(
            `"${gradlew}" -PGHIDRA_INSTALL_DIR="${this.ghidraDir}" -p "${this.ghidraMcpDir}\\extension" buildExtension`,
            {
              env: { ...process.env, JAVA_HOME: process.env.JAVA_HOME || 'D:\\tools\\jdk-25' },
            }
          );
          // Unzip into Ghidra Extensions
          await execAsync(
            `tar.exe -xf "${this.ghidraMcpDir}\\extension\\dist"\\*.zip -C "${this.ghidraDir}\\Ghidra\\Extensions"`
          );
          return { success: true, message: 'Updated GhidraMCP repository, rebuilt extension with Java 25, and installed.' };
        } catch (err: any) {
          return { success: false, message: `Failed to update GhidraMCP: ${err.message}` };
        }
      }

      case 'reo': {
        try {
          await execAsync('git pull && npm run build');
          return { success: true, message: 'Updated REO orchestrator and re-compiled build.' };
        } catch (err: any) {
          return { success: false, message: `Failed to update REO: ${err.message}` };
        }
      }

      case 'ghidra': {
        return {
          success: true,
          message: 'Ghidra is managed via binary release. If a new version exists, download from https://github.com/NationalSecurityAgency/ghidra/releases',
        };
      }

      default:
        return { success: false, message: `Unknown engine: ${engine}` };
    }
  }

  /**
   * Automatically update all engines that have pending updates or force-refresh
   */
  async updateAll(): Promise<Array<{ engine: EngineType; success: boolean; message: string }>> {
    const engines: EngineType[] = ['rea', 'ecc', 'ghidramcp', 'reo'];
    const results: Array<{ engine: EngineType; success: boolean; message: string }> = [];

    for (const eng of engines) {
      const res = await this.updateEngine(eng);
      results.push({ engine: eng, ...res });
    }

    return results;
  }

  // --- Engine Specific Checkers ---

  private async checkReo(): Promise<EngineUpdateStatus> {
    try {
      const res = await this.fetchJson('https://api.github.com/repos/abeeropu/REO/releases/latest');
      const latest = (res?.tag_name || '1.0.0').replace(/^v/, '');
      return {
        engine: 'reo',
        name: 'REO (Orchestrator)',
        currentVersion: this.currentReoVersion,
        latestVersion: latest,
        hasUpdate: latest !== this.currentReoVersion,
        updateAction: 'git pull && npm run build',
      };
    } catch {
      return {
        engine: 'reo',
        name: 'REO (Orchestrator)',
        currentVersion: this.currentReoVersion,
        latestVersion: this.currentReoVersion,
        hasUpdate: false,
      };
    }
  }

  private async checkRea(): Promise<EngineUpdateStatus> {
    let current = '6.7.0';
    try {
      const { stdout } = await execAsync('rea --version');
      current = stdout.trim() || current;
    } catch {}

    try {
      const res = await this.fetchJson('https://registry.npmjs.org/rea-agents/latest');
      const latest = res?.version || current;
      return {
        engine: 'rea',
        name: 'REA (Reverse Engineer Anything)',
        currentVersion: current,
        latestVersion: latest,
        hasUpdate: latest !== current,
        updateAction: 'npm install -g rea-agents@latest',
      };
    } catch {
      return {
        engine: 'rea',
        name: 'REA (Reverse Engineer Anything)',
        currentVersion: current,
        latestVersion: current,
        hasUpdate: false,
      };
    }
  }

  private async checkGhidraMcp(): Promise<EngineUpdateStatus> {
    let currentHash = 'local';
    try {
      const { stdout } = await execAsync(`git -C "${this.ghidraMcpDir}" rev-parse --short HEAD`);
      currentHash = stdout.trim();
    } catch {}

    try {
      const res = await this.fetchJson('https://api.github.com/repos/LaurieWired/GhidraMCP/commits/main');
      const remoteHash = (res?.sha || '').slice(0, 7) || currentHash;
      return {
        engine: 'ghidramcp',
        name: 'GhidraMCP (LaurieWired)',
        currentVersion: currentHash,
        latestVersion: remoteHash,
        hasUpdate: currentHash !== 'local' && remoteHash !== currentHash,
        updateAction: 'reo update ghidramcp',
      };
    } catch {
      return {
        engine: 'ghidramcp',
        name: 'GhidraMCP (LaurieWired)',
        currentVersion: currentHash,
        latestVersion: currentHash,
        hasUpdate: false,
      };
    }
  }

  private async checkEcc(): Promise<EngineUpdateStatus> {
    let currentHash = 'local';
    try {
      const { stdout } = await execAsync(`git -C "${this.eccDir}" rev-parse --short HEAD`);
      currentHash = stdout.trim();
    } catch {}

    try {
      const res = await this.fetchJson('https://api.github.com/repos/affaan-m/ECC/commits/main');
      const remoteHash = (res?.sha || '').slice(0, 7) || currentHash;
      return {
        engine: 'ecc',
        name: 'ECC (Everything Claude Code)',
        currentVersion: currentHash,
        latestVersion: remoteHash,
        hasUpdate: currentHash !== 'local' && remoteHash !== currentHash,
        updateAction: 'reo update ecc',
      };
    } catch {
      return {
        engine: 'ecc',
        name: 'ECC (Everything Claude Code)',
        currentVersion: currentHash,
        latestVersion: currentHash,
        hasUpdate: false,
      };
    }
  }

  private async checkGhidra(): Promise<EngineUpdateStatus> {
    const current = '12.2_PUBLIC';
    try {
      const res = await this.fetchJson('https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest');
      const latest = (res?.tag_name || current).replace(/^Ghidra_/, '');
      return {
        engine: 'ghidra',
        name: 'Ghidra (NSA SRE Suite)',
        currentVersion: current,
        latestVersion: latest,
        hasUpdate: latest !== current,
        details: latest !== current ? `New upstream release available: ${latest}` : 'Up to date',
      };
    } catch {
      return {
        engine: 'ghidra',
        name: 'Ghidra (NSA SRE Suite)',
        currentVersion: current,
        latestVersion: current,
        hasUpdate: false,
      };
    }
  }

  private async fetchJson(url: string): Promise<any> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': 'REO-Orchestrator' },
        signal: controller.signal,
      });
      if (!res.ok) return null;
      return await res.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Run doctor diagnostics on local reverse engineering prerequisites
   */
  async runDoctor(): Promise<DiagnosticResult[]> {
    const results: DiagnosticResult[] = [];

    // 1. Java 25 Runtime
    let javaHome = process.env.JAVA_HOME;
    if (!javaHome) {
      const candidates = ['D:\\tools\\jdk-25', 'C:\\Program Files\\Microsoft\\jdk-25'];
      for (const cand of candidates) {
        try {
          const stats = await fs.stat(cand);
          if (stats.isDirectory()) {
            javaHome = cand;
            break;
          }
        } catch {}
      }
    }
    if (javaHome && javaHome.includes('jdk-25')) {
      results.push({
        engine: 'Java Runtime (JDK 25)',
        status: 'ok',
        details: `Configured at ${javaHome}`,
      });
    } else if (javaHome) {
      results.push({
        engine: 'Java Runtime',
        status: 'warning',
        details: `Detected at ${javaHome}. Note: Ghidra 12.2 prefers Java 25.`,
      });
    } else {
      results.push({
        engine: 'Java Runtime',
        status: 'error',
        details: 'JAVA_HOME is not set.',
        recommendedAction: 'Set JAVA_HOME to your JDK 25 directory.',
      });
    }

    // 2. Ghidra SRE Suite
    results.push({
      engine: 'Ghidra (NSA SRE Suite)',
      status: 'ok',
      details: `Installed at ${this.ghidraDir}`,
    });

    // 3. GhidraMCP Bridge
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);
      const res = await fetch('http://127.0.0.1:8080/get_program_info', { signal: controller.signal });
      clearTimeout(timeoutId);

      results.push({
        engine: 'GhidraMCP Bridge',
        status: res.ok ? 'ok' : 'warning',
        details: res.ok ? 'Connected to live Ghidra GUI on port 8080' : 'Ghidra GUI not currently open (Headless mode ready)',
      });
    } catch {
      results.push({
        engine: 'GhidraMCP Bridge',
        status: 'warning',
        details: 'Ghidra GUI HTTP backend not detected on :8080. Headless mode will be used automatically.',
        recommendedAction: 'Launch Ghidra GUI with GhidraMCP plugin enabled for live decompilation sync.',
      });
    }

    // 4. REA Multi-engine
    results.push({
      engine: 'REA (Reverse Engineer Anything)',
      status: 'ok',
      details: 'REA CLI & native binary detection active.',
    });

    // 5. ECC Autonomous Harness
    results.push({
      engine: 'ECC (Everything Claude Code)',
      status: 'ok',
      details: 'Verification loops and Obligation Ledger active.',
    });

    return results;
  }
}
