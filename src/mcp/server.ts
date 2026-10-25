import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { OrchestratorPipeline } from '../orchestrator/pipeline.js';
import { UpdaterManager } from '../updater/index.js';

export class ReoMcpServer {
  private server: Server;
  private pipeline: OrchestratorPipeline;
  private updater: UpdaterManager;

  constructor() {
    this.server = new Server(
      {
        name: 'reo-orchestrator',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.pipeline = new OrchestratorPipeline();
    this.updater = new UpdaterManager();
    this.registerHandlers();
  }

  private registerHandlers(): void {
    // List Tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'reo_analyze',
            description:
              'Autonomous reverse engineering pipeline: Triages binary format with REA, runs Ghidra decompiler, executes Frida dynamic tracing, writes discoveries back into Ghidra DB, and produces verified source with ECC.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Absolute or relative path to target binary, APK, ELF, PE, or firmware file.',
                },
                targetFunction: {
                  type: 'string',
                  description: 'Optional function address (e.g. 0x140001000) or symbol name to focus on.',
                },
                enableDynamicTracing: {
                  type: 'boolean',
                  description: 'Whether to run dynamic Frida/Rizin tracing to capture decrypted memory and arguments.',
                  default: true,
                },
              },
              required: ['filePath'],
            },
          },
          {
            name: 'reo_decompile',
            description: 'Direct high-level C/C++ AST decompilation of a target function with xrefs and variable types.',
            inputSchema: {
              type: 'object',
              properties: {
                address: {
                  type: 'string',
                  description: 'Hex address of target function (e.g. 0x401000 or 0x140001000).',
                },
              },
              required: ['address'],
            },
          },
          {
            name: 'reo_trace_and_annotate',
            description:
              'Dynamic-static bridge: Traces live runtime arguments and decrypted buffers with Frida, then annotates comments and types directly into Ghidra decompiler.',
            inputSchema: {
              type: 'object',
              properties: {
                filePath: {
                  type: 'string',
                  description: 'Path to binary.',
                },
                address: {
                  type: 'string',
                  description: 'Function address to hook.',
                },
              },
              required: ['filePath', 'address'],
            },
          },
          {
            name: 'reo_doctor',
            description: 'Diagnoses reverse engineering prerequisites (Java 25, Ghidra, GhidraMCP, REA, and ECC).',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
        ],
      };
    });

    // Call Tool
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        if (name === 'reo_analyze') {
          const filePath = String(args?.filePath || '');
          const targetFunction = args?.targetFunction ? String(args.targetFunction) : undefined;
          const enableDynamicTracing = args?.enableDynamicTracing !== false;

          const report = await this.pipeline.run(filePath, { targetFunction, enableDynamicTracing });
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(report, null, 2),
              },
            ],
          };
        }

        if (name === 'reo_doctor') {
          const diagnostics = await this.updater.runDoctor();
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(diagnostics, null, 2),
              },
            ],
          };
        }

        if (name === 'reo_decompile') {
          const address = String(args?.address || '');
          const ghidra = (this.pipeline as any).ghidra;
          const fn = await ghidra.decompileFunction(address);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(fn, null, 2),
              },
            ],
          };
        }

        if (name === 'reo_trace_and_annotate') {
          const filePath = String(args?.filePath || '');
          const address = String(args?.address || '');
          const rea = (this.pipeline as any).rea;
          const feedback = (this.pipeline as any).feedback;

          const trace = await rea.traceFunction(filePath, address);
          const syncResult = await feedback.syncTraceToGhidra(trace);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ trace, syncResult }, null, 2),
              },
            ],
          };
        }

        throw new Error(`Unknown tool: ${name}`);
      } catch (err: any) {
        return {
          content: [
            {
              type: 'text',
              text: `REO Error: ${err.message || String(err)}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}
