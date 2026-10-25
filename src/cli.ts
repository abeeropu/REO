#!/usr/bin/env node
import { Command } from 'commander';
import * as fs from 'node:fs/promises';
import { OrchestratorPipeline } from './orchestrator/pipeline.js';
import { ReoMcpServer } from './mcp/server.js';
import { UpdaterManager } from './updater/index.js';

const program = new Command();
const updater = new UpdaterManager();

program
  .name('reo')
  .description('REO (Reverse Engineering Orchestrator) — Autonomous SRE Conductor for Ghidra, REA & ECC')
  .version('1.0.0');

// Command: analyze
program
  .command('analyze <file>')
  .description('Autonomously reverse engineer a binary, APK, or firmware file')
  .option('-f, --function <address>', 'Focus analysis on a specific function address')
  .option('-o, --output <file>', 'Save Markdown analysis report to file')
  .option('--no-trace', 'Disable dynamic Frida tracing')
  .action(async (file, options) => {
    console.log(`\n🔍 [REO] Initiating Autonomous SRE Pipeline for: ${file}`);
    console.log(`⚡ Phase 1: Ingestion & Auto-Triage (REA Engine)`);
    console.log(`⚡ Phase 2: Engine Binding & Ghidra SRE Decompilation`);
    console.log(`⚡ Phase 3: Dynamic Validation & Static-Dynamic Sync`);
    console.log(`⚡ Phase 4: ECC Quality Synthesis & Security Audit\n`);

    const pipeline = new OrchestratorPipeline();
    const report = await pipeline.run(file, {
      targetFunction: options.function,
      enableDynamicTracing: options.trace,
    });

    console.log(`\n================================================================`);
    console.log(`                REO ANALYSIS COMPLETE                           `);
    console.log(`================================================================\n`);
    console.log(report.executiveSummary);
    console.log(`\nSecurity Findings: ${report.securityFindings.length}`);
    report.securityFindings.forEach((f) => {
      console.log(`  [${f.severity.toUpperCase()}] ${f.title}: ${f.description}`);
    });

    if (options.output) {
      const markdown = [
        `# REO Analysis Report: ${file}`,
        '',
        report.executiveSummary,
        '',
        '## Architecture Diagram',
        report.architectureDiagram,
        '',
        '## Security Audit Findings',
        ...report.securityFindings.map((f) => `- **[${f.severity.toUpperCase()}]** ${f.title}: ${f.description} *(Remediation: ${f.remediation})*`),
        '',
        '## Reconstructed Source Code',
        '```c',
        report.reconstructedModernSource,
        '```',
      ].join('\n');

      await fs.writeFile(options.output, markdown, 'utf-8');
      console.log(`\n📄 Report saved to: ${options.output}`);
    }
  });

// Command: serve (MCP server)
program
  .command('serve')
  .description('Start the REO Model Context Protocol (MCP) server on stdio')
  .action(async () => {
    const server = new ReoMcpServer();
    await server.start();
  });

// Command: doctor
program
  .command('doctor')
  .description('Diagnose Ghidra, Java 25, GhidraMCP, and REA engine prerequisites')
  .action(async () => {
    console.log('\n🩺 [REO Doctor] Checking Reverse Engineering Environment...\n');
    const diagnostics = await updater.runDoctor();

    diagnostics.forEach((d) => {
      const icon = d.status === 'ok' ? '✅' : d.status === 'warning' ? '⚠️' : '❌';
      console.log(`${icon} ${d.engine}: ${d.details}`);
      if (d.recommendedAction) {
        console.log(`   👉 Action: ${d.recommendedAction}`);
      }
    });
    console.log('');
  });

// Command: update (Orchestrated multi-engine update)
program
  .command('update [engine]')
  .description('Automatically check and update REO, REA, GhidraMCP, and ECC')
  .option('-c, --check', 'Check for updates across all engines without applying them')
  .action(async (engine, options) => {
    console.log('\n🔄 [REO Orchestrator] Checking update status across all engines...\n');
    const statuses = await updater.checkAll();

    statuses.forEach((s) => {
      const icon = s.hasUpdate ? '🔔' : '✅';
      const statusText = s.hasUpdate ? `Update available: ${s.currentVersion} -> ${s.latestVersion}` : `Up to date (${s.currentVersion})`;
      console.log(`${icon} ${s.name}: ${statusText}`);
      if (s.details) console.log(`   ℹ️ ${s.details}`);
    });

    if (options.check) {
      console.log('\nCheck complete. To apply updates, run: reo update\n');
      return;
    }

    const targetEngine = engine ? (engine.toLowerCase() as any) : 'all';
    console.log(`\n⚡ Applying updates for: ${targetEngine.toUpperCase()}...`);

    if (targetEngine === 'all') {
      const results = await updater.updateAll();
      console.log('');
      results.forEach((r) => {
        const icon = r.success ? '✅' : '❌';
        console.log(`${icon} [${r.engine.toUpperCase()}]: ${r.message}`);
      });
      console.log('\n✨ All orchestrated engines updated successfully!\n');
    } else {
      const res = await updater.updateEngine(targetEngine);
      const icon = res.success ? '✅' : '❌';
      console.log(`\n${icon} [${targetEngine.toUpperCase()}]: ${res.message}\n`);
    }
  });

program.parse(process.argv);
