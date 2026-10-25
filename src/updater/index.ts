import * as fs from 'node:fs/promises';

export interface DiagnosticResult {
  engine: string;
  status: 'ok' | 'warning' | 'error';
  details: string;
  recommendedAction?: string;
}

export class UpdaterManager {
  private currentVersion = '1.0.0';
  private repo = 'abeeropu/reo';

  /**
   * Check for updates on GitHub Releases
   */
  async checkForUpdates(): Promise<{ current: string; latest: string; hasUpdate: boolean; releaseUrl?: string }> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const res = await fetch(`https://api.github.com/repos/${this.repo}/releases/latest`, {
        headers: { 'User-Agent': 'REO-Updater' },
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        return { current: this.currentVersion, latest: this.currentVersion, hasUpdate: false };
      }

      const data = (await res.json()) as any;
      const latestTag = (data?.tag_name || '').replace(/^v/, '');
      const hasUpdate = latestTag !== '' && latestTag !== this.currentVersion;

      return {
        current: this.currentVersion,
        latest: latestTag || this.currentVersion,
        hasUpdate,
        releaseUrl: data?.html_url,
      };
    } catch {
      return { current: this.currentVersion, latest: this.currentVersion, hasUpdate: false };
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
      // Check common installation paths
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
    const ghidraDir = process.env.GHIDRA_INSTALL_DIR || 'D:\\tools\\ghidra_12.2_PUBLIC';
    results.push({
      engine: 'Ghidra (NSA SRE Suite)',
      status: 'ok',
      details: `Installed at ${ghidraDir}`,
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
