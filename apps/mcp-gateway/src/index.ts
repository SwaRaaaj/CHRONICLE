import http from 'node:http';
import { canonicalHash } from '@chronicle/crypto-primitives';
import type { ActionRequest, AuthorizationGrant, AuthorizationDecision } from '@chronicle/core-types';
import { ENTERPRISE_TOOL_CATALOG, MockEnterpriseToolsService } from '../../mock-enterprise-tools/src/index.ts';

export interface McpGatewayConfig {
  controlPlaneUrl: string;
  toolsService: MockEnterpriseToolsService;
  port?: number;
}

export class McpSecurityGateway {
  private config: McpGatewayConfig;

  constructor(config: McpGatewayConfig) {
    this.config = config;
  }

  /**
   * Process MCP tools/list request.
   */
  public handleToolsList(): { tools: unknown[] } {
    const tools = ENTERPRISE_TOOL_CATALOG.map(t => ({
      name: t.name,
      description: `[Chronicle Guarded | Risk: ${t.riskClass}] ${t.description}`,
      inputSchema: {
        type: 'object',
        properties: Object.fromEntries(
          Object.entries(t.parametersSchema).map(([k, v]) => [k, { type: v }])
        )
      },
      _chronicle: {
        riskClass: t.riskClass,
        requiresGrant: t.requiresGrant,
        category: t.category
      }
    }));

    return { tools };
  }

  /**
   * Process MCP tools/call request through Chronicle authorization interception.
   */
  public async handleToolCall(
    agentId: string,
    delegationId: string,
    sessionId: string,
    taskId: string,
    tenantId: string,
    toolName: string,
    parameters: Record<string, unknown>,
    authorizer: (req: ActionRequest) => Promise<AuthorizationDecision>
  ): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
    chronicleDecision: AuthorizationDecision;
  }> {
    const actionId = 'act_' + Math.random().toString(36).substring(2, 12);
    const parametersHash = canonicalHash(parameters);
    const timestamp = new Date().toISOString();

    const actionRequest: ActionRequest = {
      actionId,
      tenantId,
      sessionId,
      taskId,
      agentId,
      delegationId,
      actionType: toolName,
      tool: toolName,
      resource: {
        id: `res_${toolName}_${parameters.customerId || parameters.destinationAccount || parameters.database || 'default'}`,
        type: toolName,
        sensitivity: toolName.includes('database') || toolName.includes('wire') ? 'CRITICAL' : (toolName.includes('pii') ? 'CONFIDENTIAL' : 'INTERNAL'),
        environment: 'production'
      },
      parameters,
      parametersHash,
      timestamp
    };

    // 1. Intercept call and ask Chronicle Control Plane for Authorization
    const decision = await authorizer(actionRequest);

    // 2. Handle Decision Effects
    if (decision.decision === 'DENY') {
      return {
        isError: true,
        chronicleDecision: decision,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'CHRONICLE_SECURITY_INTERCEPT_DENY',
              actionId,
              reasonCodes: decision.reasonCodes,
              explanation: decision.explanation,
              riskScore: decision.riskScore,
              riskClass: decision.riskClass
            }, null, 2)
          }
        ]
      };
    }

    if (decision.decision === 'HOLD') {
      return {
        isError: true,
        chronicleDecision: decision,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'CHRONICLE_ACTION_HELD',
              approvalId: decision.approvalId,
              actionId,
              explanation: decision.explanation,
              requiredApprovalRole: decision.requiredApprovalRole,
              notice: 'Action paused pending human sponsor step-up sign-off.'
            }, null, 2)
          }
        ]
      };
    }

    // 3. ALLOW: Forward call to enterprise tools carrying cryptographic grant
    const toolExecResult = this.config.toolsService.execute(toolName, parameters, decision.grant);

    if (!toolExecResult.success) {
      return {
        isError: true,
        chronicleDecision: decision,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'TOOL_EXECUTION_FAILURE',
              details: toolExecResult.error,
              code: toolExecResult.code
            }, null, 2)
          }
        ]
      };
    }

    return {
      isError: false,
      chronicleDecision: decision,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            result: toolExecResult.data,
            chronicleVerified: true,
            grantId: decision.grant?.grantId,
            actionId
          }, null, 2)
        }
      ]
    };
  }

  public createHttpServer(
    port: number = 3001,
    authorizer: (req: ActionRequest) => Promise<AuthorizationDecision>
  ): http.Server {
    const server = http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      // MCP JSON-RPC 2.0 endpoint
      if (req.method === 'POST' && url.pathname === '/mcp') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const rpc = JSON.parse(body);
            const id = rpc.id;

            if (rpc.method === 'tools/list') {
              const result = this.handleToolsList();
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
              return;
            }

            if (rpc.method === 'tools/call') {
              const { name, arguments: params, _chronicleContext } = rpc.params || {};
              const agentId = _chronicleContext?.agentId || 'agent_default';
              const delegationId = _chronicleContext?.delegationId || 'del_default';
              const sessionId = _chronicleContext?.sessionId || 'sess_default';
              const taskId = _chronicleContext?.taskId || 'task_default';
              const tenantId = _chronicleContext?.tenantId || 'tenant_acme';

              const callResult = await this.handleToolCall(
                agentId,
                delegationId,
                sessionId,
                taskId,
                tenantId,
                name,
                params || {},
                authorizer
              );

              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ jsonrpc: '2.0', id, result: callResult }));
              return;
            }

            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: { code: -32601, message: 'Method not found' }
            }));
          } catch (err: unknown) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'MCP Gateway endpoint is POST /mcp' }));
    });

    return server;
  }
}

// Standalone runner for npm run start:mcp-gateway
if (process.argv[1]?.endsWith('mcp-gateway/src/index.ts')) {
  const toolsService = new MockEnterpriseToolsService('');
  const gateway = new McpSecurityGateway({
    controlPlaneUrl: 'http://localhost:3000',
    toolsService
  });

  const authorizer = async (req: ActionRequest): Promise<AuthorizationDecision> => {
    try {
      const res = await fetch('http://localhost:3000/api/v1/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req)
      });
      return await res.json() as AuthorizationDecision;
    } catch {
      return {
        actionId: req.actionId,
        decision: 'DENY',
        reasonCodes: ['POLICY_DENY'],
        explanation: 'Chronicle Control Plane unreachable at http://localhost:3000',
        policyVersion: 'v1',
        riskScore: 100,
        riskClass: 'CRITICAL',
        evaluatedAt: new Date().toISOString(),
        latencyMs: 0
      };
    }
  };

  const server = gateway.createHttpServer(3001, authorizer);
  server.listen(3001, () => {
    console.log('[Chronicle MCP Gateway] Online at http://localhost:3001/mcp');
    console.log('[Chronicle MCP Gateway] Intercepting agent tool calls with zero-trust validation');
  });
}
