import http from 'node:http';
import { verifyAuthorizationGrant, canonicalHash } from '@chronicle/crypto-primitives';
import type { AuthorizationGrant } from '@chronicle/core-types';

export interface ToolDefinition {
  name: string;
  category: 'PAYMENT' | 'CRM' | 'CLOUD' | 'COMMS';
  description: string;
  riskClass: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  requiresGrant: boolean;
  parametersSchema: Record<string, string>;
}

export const ENTERPRISE_TOOL_CATALOG: ToolDefinition[] = [
  // 1. Payments
  {
    name: 'stripe_refund',
    category: 'PAYMENT',
    description: 'Process a customer payment refund via Stripe',
    riskClass: 'HIGH',
    requiresGrant: true,
    parametersSchema: { chargeId: 'string', amount: 'number', reason: 'string' }
  },
  {
    name: 'send_wire_transfer',
    category: 'PAYMENT',
    description: 'Dispatch an outbound SWIFT/ACH corporate wire transfer',
    riskClass: 'CRITICAL',
    requiresGrant: true,
    parametersSchema: { destinationAccount: 'string', amount: 'number', currency: 'string' }
  },
  {
    name: 'generate_invoice',
    category: 'PAYMENT',
    description: 'Generate customer billing invoice',
    riskClass: 'LOW',
    requiresGrant: false,
    parametersSchema: { customerId: 'string', items: 'array', total: 'number' }
  },

  // 2. CRM
  {
    name: 'search_customers',
    category: 'CRM',
    description: 'Search customer accounts by query',
    riskClass: 'LOW',
    requiresGrant: false,
    parametersSchema: { query: 'string' }
  },
  {
    name: 'read_customer_pii',
    category: 'CRM',
    description: 'Read full customer record including SSN, address, and credit history',
    riskClass: 'HIGH',
    requiresGrant: true,
    parametersSchema: { customerId: 'string' }
  },
  {
    name: 'update_customer_record',
    category: 'CRM',
    description: 'Update customer contact details or subscription tier',
    riskClass: 'MEDIUM',
    requiresGrant: true,
    parametersSchema: { customerId: 'string', updates: 'object' }
  },

  // 3. Cloud Infrastructure
  {
    name: 'query_production_database',
    category: 'CLOUD',
    description: 'Execute SQL query against production cluster database',
    riskClass: 'CRITICAL',
    requiresGrant: true,
    parametersSchema: { sql: 'string', database: 'string' }
  },
  {
    name: 'modify_security_group',
    category: 'CLOUD',
    description: 'Modify cloud firewall / ingress security group rules',
    riskClass: 'CRITICAL',
    requiresGrant: true,
    parametersSchema: { groupId: 'string', port: 'number', cidr: 'string' }
  },
  {
    name: 'deploy_container',
    category: 'CLOUD',
    description: 'Deploy docker container to production Kubernetes cluster',
    riskClass: 'HIGH',
    requiresGrant: true,
    parametersSchema: { image: 'string', replicas: 'number' }
  },

  // 4. Communications
  {
    name: 'send_external_email',
    category: 'COMMS',
    description: 'Transmit outbound customer or vendor email via SendGrid',
    riskClass: 'MEDIUM',
    requiresGrant: true,
    parametersSchema: { to: 'string', subject: 'string', body: 'string' }
  },
  {
    name: 'post_slack_announcement',
    category: 'COMMS',
    description: 'Broadcast announcement to internal enterprise Slack channel',
    riskClass: 'LOW',
    requiresGrant: false,
    parametersSchema: { channel: 'string', message: 'string' }
  }
];

export class MockEnterpriseToolsService {
  private controlPlanePublicKeyPem: string;

  constructor(controlPlanePublicKeyPem: string) {
    this.controlPlanePublicKeyPem = controlPlanePublicKeyPem;
  }

  /**
   * Execute enterprise tool with cryptographic grant enforcement.
   */
  public execute(
    toolName: string,
    parameters: Record<string, unknown>,
    grant?: AuthorizationGrant
  ): { success: boolean; data?: unknown; error?: string; code?: string } {
    const def = ENTERPRISE_TOOL_CATALOG.find(t => t.name === toolName);
    if (!def) {
      return { success: false, error: `Tool '${toolName}' not found in enterprise catalog`, code: 'TOOL_NOT_FOUND' };
    }

    // Cryptographic grant verification for sensitive tools
    if (def.requiresGrant) {
      if (!grant) {
        return {
          success: false,
          error: `Execution denied: Tool '${toolName}' strictly requires a signed Chronicle AuthorizationGrant`,
          code: 'GRANT_REQUIRED'
        };
      }

      const grantCheck = verifyAuthorizationGrant(
        grant,
        toolName,
        parameters,
        this.controlPlanePublicKeyPem
      );

      if (!grantCheck.valid) {
        return {
          success: false,
          error: `Cryptographic grant rejected: ${grantCheck.reason}`,
          code: grantCheck.reason || 'INVALID_GRANT'
        };
      }
    }

    // Tool logic simulation
    switch (toolName) {
      case 'stripe_refund':
        return {
          success: true,
          data: {
            refundId: 're_' + Math.random().toString(36).substring(2, 14),
            chargeId: parameters.chargeId,
            amountRefunded: parameters.amount,
            status: 'succeeded',
            timestamp: new Date().toISOString()
          }
        };

      case 'send_wire_transfer':
        return {
          success: true,
          data: {
            transferId: 'wire_' + Math.random().toString(36).substring(2, 14),
            destinationAccount: parameters.destinationAccount,
            amount: parameters.amount,
            currency: parameters.currency || 'USD',
            status: 'EXECUTED_BY_CORE_BANKING',
            clearedAt: new Date().toISOString()
          }
        };

      case 'generate_invoice':
        return {
          success: true,
          data: {
            invoiceNumber: 'INV-2026-' + Math.floor(1000 + Math.random() * 9000),
            customerId: parameters.customerId,
            total: parameters.total,
            status: 'ISSUED'
          }
        };

      case 'search_customers':
        return {
          success: true,
          data: {
            results: [
              { customerId: 'cust_9821', name: 'Acme Corp', tier: 'ENTERPRISE', status: 'ACTIVE' },
              { customerId: 'cust_4412', name: 'Globex Inc', tier: 'STANDARD', status: 'ACTIVE' }
            ]
          }
        };

      case 'read_customer_pii':
        return {
          success: true,
          data: {
            customerId: parameters.customerId,
            name: 'Jane Doe',
            ssnMasked: '***-**-4912',
            email: 'jane.doe@example.com',
            homeAddress: '742 Evergreen Terrace, Springfield, OR',
            creditRating: 780,
            accessNotice: 'CONFIDENTIAL_CUSTOMER_DATA_ACCESSED'
          }
        };

      case 'update_customer_record':
        return {
          success: true,
          data: {
            customerId: parameters.customerId,
            updatedFields: parameters.updates,
            modifiedAt: new Date().toISOString()
          }
        };

      case 'query_production_database':
        return {
          success: true,
          data: {
            database: parameters.database || 'prod_core',
            rowsReturned: 3,
            rows: [
              { id: 1, name: 'System Cluster 1', status: 'HEALTHY' },
              { id: 2, name: 'Payment Ledger Primary', status: 'SYNCHRONIZED' }
            ]
          }
        };

      case 'modify_security_group':
        return {
          success: true,
          data: {
            groupId: parameters.groupId,
            ruleAdded: `ALLOW TCP ${parameters.port} from ${parameters.cidr}`,
            status: 'APPLIED_TO_VPC'
          }
        };

      case 'deploy_container':
        return {
          success: true,
          data: {
            image: parameters.image,
            replicas: parameters.replicas || 2,
            deploymentId: 'dep_' + Math.random().toString(36).substring(2, 10),
            status: 'RUNNING'
          }
        };

      case 'send_external_email':
        return {
          success: true,
          data: {
            messageId: 'msg_' + Math.random().toString(36).substring(2, 14),
            recipient: parameters.to,
            subject: parameters.subject,
            deliveryStatus: 'DELIVERED_TO_GATEWAY'
          }
        };

      case 'post_slack_announcement':
        return {
          success: true,
          data: {
            channel: parameters.channel,
            ts: Date.now().toString(),
            status: 'POSTED'
          }
        };

      default:
        return { success: true, data: { executed: toolName, params: parameters } };
    }
  }

  public createHttpServer(port: number = 3002): http.Server {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      // CORS headers
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Chronicle-Grant');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method === 'GET' && url.pathname === '/tools') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(ENTERPRISE_TOOL_CATALOG, null, 2));
        return;
      }

      if (req.method === 'POST' && url.pathname === '/execute') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const payload = JSON.parse(body);
            const toolName = payload.tool;
            const parameters = payload.parameters || {};

            let grant: AuthorizationGrant | undefined = payload.grant;
            const headerGrant = req.headers['x-chronicle-grant'];
            if (!grant && typeof headerGrant === 'string') {
              grant = JSON.parse(headerGrant);
            }

            const result = this.execute(toolName, parameters, grant);
            const statusCode = result.success ? 200 : (result.code === 'GRANT_REQUIRED' || result.code === 'INVALID_GRANT' || result.code?.includes('TAMPERED') ? 403 : 400);

            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result, null, 2));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: (err as Error).message }));
          }
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found' }));
    });

    return server;
  }
}

// Standalone start support
if (process.argv[1]?.endsWith('mock-enterprise-tools/src/index.ts')) {
  const dummyKey = ''; // In standalone, will be configured
  const svc = new MockEnterpriseToolsService(dummyKey);
  const server = svc.createHttpServer(3002);
  server.listen(3002, () => {
    console.log('[Mock Enterprise Tools] Online at http://localhost:3002');
  });
}
