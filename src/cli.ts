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

// Command: update
program
  .command('update')
  .description('Check for updates and release news')
  .action(async () => {
    console.log('\n🔄 [REO Updater] Checking for updates on GitHub...');
    const result = await updater.checkForUpdates();

    if (result.hasUpdate) {
      console.log(`\n🚀 New version available: v${result.latest} (current: v${result.current})`);
      if (result.releaseUrl) console.log(`👉 Release notes: ${result.releaseUrl}`);
      console.log(`To update, run: npm install -g reo-sre@latest\n`);
    } else {
      console.log(`✅ REO is up to date (version v${result.current}).\n`);
    }
  });

program.parse(process.argv);
