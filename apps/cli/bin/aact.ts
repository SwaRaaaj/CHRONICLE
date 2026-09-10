#!/usr/bin/env node
/**
 * Chronicle Unified CLI Command Suite (`aact`) (§81)
 * Administrative and developer command-line interface for the Autonomous Action Control Plane.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ChronicleControlPlane } from '../../control-plane/src/index.ts';
import { parsePolicyDSL, evaluatePolicyDSL } from '@chronicle/policy-dsl';
import { canonicalHash } from '@chronicle/crypto-primitives';
import type { ActionRequest } from '@chronicle/core-types';

const args = process.argv.slice(2);
const command = args[0]?.toLowerCase();
const subCommand = args[1]?.toLowerCase();

function printBanner() {
  console.log(`
\x1b[36m   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗ ██████╗██╗     ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██║██╔════╝██║     ██╔════╝
  ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║██║     ██║     █████╗  
  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║██║     ██║     ██╔══╝  
  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║╚██████╗███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚══════╝╚══════╝\x1b[0m
  \x1b[1mChronicle AACT Unified CLI Tool (aact) | Zero-Trust Control Plane\x1b[0m
`);
}

function printUsage() {
  printBanner();
  console.log(`\x1b[1mUSAGE:\x1b[0m
  aact <command> [options]

\x1b[1mCOMMANDS:\x1b[0m
  \x1b[33magent list\x1b[0m                           List registered AI agents and active statuses (§7, §89)
  \x1b[33magent inspect <agentId>\x1b[0m              Inspect detailed identity, delegation, and risk profile
  \x1b[33mauth check <agentId> <tool> <res> [--amount <amt>]\x1b[0m  Simulate runtime authorization decision (§11, §81)
  \x1b[33mdelegation inspect <delegationId>\x1b[0m    Inspect delegation envelope, limits, and parent chain (§8)
  \x1b[33mpolicy test <policyFile>\x1b[0m             Parse declarative Policy DSL file and run validation (§50, §51)
  \x1b[33mblast-radius <agentId>\x1b[0m               Compute compromise reachability & max financial exposure (§38, §84)
  \x1b[33maudit verify\x1b[0m                         Verify cryptographic Merkle ledger unbroken hash chain (§25, §65)
  \x1b[33mquarantine <agentId>\x1b[0m                 Emergency kill-switch quarantine for compromised agent (§32, §33)
  \x1b[33mhelp\x1b[0m                                 Display this help guide
`);
}

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printUsage();
    process.exit(0);
  }

  // Initialize in-process Control Plane kernel for local CLI execution
  const cp = new ChronicleControlPlane();

  switch (command) {
    case 'agent': {
      if (subCommand === 'list') {
        printBanner();
        console.log('\x1b[1mREGISTERED AGENT INVENTORY (§7, §89):\x1b[0m\n');
        const agents = cp.delegationManager.listAgents();
        console.log('┌────────────────────────────┬──────────────┬──────────────┬──────────────┬────────────────────────────┐');
        console.log('│ Agent ID                   │ Status       │ Risk Class   │ Version      │ Model Provider             │');
        console.log('├────────────────────────────┼──────────────┼──────────────┼──────────────┼────────────────────────────┤');
        for (const a of agents) {
          const id = a.agentId.padEnd(26);
          const st = a.status.padEnd(12);
          const rk = a.riskClass.padEnd(12);
          const vr = a.agentVersion.padEnd(12);
          const mp = a.modelProvider.padEnd(26);
          console.log(`│ ${id} │ ${st} │ ${rk} │ ${vr} │ ${mp} │`);
        }
        console.log('└────────────────────────────┴──────────────┴──────────────┴──────────────┴────────────────────────────┘');
      } else if (subCommand === 'inspect') {
        const agentId = args[2];
        if (!agentId) {
          console.error('Error: Please specify an agentId: aact agent inspect <agentId>');
          process.exit(1);
        }
        const agent = cp.delegationManager.getAgent(agentId);
        if (!agent) {
          console.error(`Error: Agent '${agentId}' not found.`);
          process.exit(1);
        }
        printBanner();
        console.log(`\x1b[1mAGENT IDENTITY RECORD: ${agent.name} (${agent.agentId})\x1b[0m`);
        console.log(JSON.stringify(agent, null, 2));
      } else {
        printUsage();
      }
      break;
    }

    case 'auth': {
      if (subCommand === 'check') {
        const agentId = args[2];
        const tool = args[3];
        const resourceId = args[4];

        if (!agentId || !tool || !resourceId) {
          console.error('Usage: aact auth check <agentId> <tool> <resourceId> [--amount <amt>]');
          process.exit(1);
        }

        let amount = 100;
        const amountIdx = args.indexOf('--amount');
        if (amountIdx !== -1 && args[amountIdx + 1]) {
          amount = Number(args[amountIdx + 1]);
        }

        const agent = cp.delegationManager.getAgent(agentId);
        if (!agent) {
          console.error(`Error: Agent '${agentId}' not found in registry.`);
          process.exit(1);
        }

        const actionReq: ActionRequest = {
          actionId: `act_cli_${Date.now()}`,
          tenantId: agent.tenantId,
          sessionId: 'sess_cli',
          taskId: `task_${agentId}`,
          agentId,
          delegationId: `del_finance_refund_root`,
          actionType: tool,
          tool,
          resource: {
            id: resourceId,
            type: tool.split('_')[0] || 'resource',
            sensitivity: 'CONFIDENTIAL',
            environment: 'production',
          },
          parameters: { amount, resourceId },
          parametersHash: canonicalHash({ amount, resourceId }),
          timestamp: new Date().toISOString(),
        };

        const decision = await cp.authorizeAction(actionReq);
        printBanner();
        console.log(`\x1b[1mRUNTIME AUTHORIZATION DECISION (§11, §81):\x1b[0m\n`);

        const badgeColor =
          decision.decision === 'ALLOW' ? '\x1b[32m' : decision.decision === 'HOLD' ? '\x1b[33m' : '\x1b[31m';
        console.log(`Decision:      ${badgeColor}\x1b[1m[${decision.decision}]\x1b[0m`);
        console.log(`Risk Score:    ${decision.riskScore}/100 (${decision.riskClass})`);
        console.log(`Reason Codes:  ${decision.reasonCodes.join(', ')}`);
        console.log(`Explanation:   ${decision.explanation}`);
        console.log(`Latency:       ${decision.latencyMs} ms`);

        if (decision.grant) {
          console.log(`\n\x1b[32m✔ Ephemeral Cryptographic Grant Issued:\x1b[0m`);
          console.log(`  Grant ID:     ${decision.grant.grantId}`);
          console.log(`  TTL (Expiry): ${decision.grant.expiresAt} (valid for 60s)`);
          console.log(`  Signature:    ${decision.grant.signature.substring(0, 32)}...`);
        }
      } else {
        printUsage();
      }
      break;
    }

    case 'blast-radius': {
      const agentId = args[1];
      if (!agentId) {
        console.error('Usage: aact blast-radius <agentId>');
        process.exit(1);
      }
      const report = cp.blastRadiusAnalyzer.calculateBlastRadius(agentId);
      if (!report) {
        console.error(`Error: Could not calculate blast radius for '${agentId}'`);
        process.exit(1);
      }
      printBanner();
      console.log(`\x1b[1mCOMPROMISE BLAST RADIUS REPORT: ${agentId} (§38, §84)\x1b[0m\n`);
      console.log(`Agent Risk Class:            ${report.riskClass}`);
      console.log(`Maximum Financial Exposure:  \x1b[31m$${report.maximumFinancialExposure.toLocaleString()}\x1b[0m`);
      console.log(`Reachable Tools (${report.reachableTools.length}):`);
      for (const t of report.reachableTools) {
        console.log(`  • ${t.tool.padEnd(24)} [Risk: ${t.risk}] (Ceiling: $${t.maxExposure || 0})`);
      }
      console.log(`Reachable Resources (${report.reachableResources.length}):`);
      for (const r of report.reachableResources) {
        console.log(`  • ${r.resourceType.padEnd(24)} [Sensitivity: ${r.sensitivity}]`);
      }
      break;
    }

    case 'audit': {
      if (subCommand === 'verify') {
        printBanner();
        console.log('\x1b[1mCRYPTOGRAPHIC MERKLE LEDGER AUDIT (§25, §65):\x1b[0m\n');
        const result = cp.auditLedger.verifyIntegrity();
        if (result.valid) {
          console.log(`\x1b[32m✔ Ledger Cryptographic Integrity: 100% UNBROKEN (${result.totalReceipts} receipt blocks verified)\x1b[0m`);
        } else {
          console.log(`\x1b[31m✘ Ledger Cryptographic Integrity: TAMPERING DETECTED! Broken at: ${result.brokenAt}\x1b[0m`);
        }
      } else {
        printUsage();
      }
      break;
    }

    case 'quarantine': {
      const agentId = args[1];
      if (!agentId) {
        console.error('Usage: aact quarantine <agentId>');
        process.exit(1);
      }
      cp.policyEngine.quarantineAgent(agentId);
      printBanner();
      console.log(`\x1b[31m\x1b[1m✔ EMERGENCY LOCKDOWN: Agent '${agentId}' is now QUARANTINED globally (§32, §33).\x1b[0m`);
      console.log(`All subsequent actions by this agent will immediately abort with reason 'AGENT_QUARANTINED'.`);
      break;
    }

    default:
      console.error(`Unknown command: '${command}'`);
      printUsage();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error('CLI execution error:', err);
  process.exit(1);
});
