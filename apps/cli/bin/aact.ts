#!/usr/bin/env node
/**
 * Chronicle Unified CLI Command Suite (`aact`) (§81)
 * Administrative and developer command-line interface for the Autonomous Action Control Plane.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { ChronicleControlPlane } from '../../control-plane/src/index.ts';
import { parsePolicyDSL, evaluatePolicyDSL, runPolicyTests } from '@chronicle/policy-dsl';
import { canonicalHash } from '@chronicle/crypto-primitives';
import { AIPolicyAssistant } from '@chronicle/ai';
import type { ActionRequest, PolicyTestCase, ActionContext } from '@chronicle/core-types';
import type { ChronicleControlPlane as ChronicleControlPlaneType } from '../../control-plane/src/index.ts';

/** Walks the parentDelegationId chain to compute how many hops a delegation is from its root sponsor. */
function computeDelegationDepth(cp: ChronicleControlPlaneType, delegationId: string): number {
  let depth = 0;
  let current = cp.delegationManager.getDelegation(delegationId);
  while (current?.parentDelegationId) {
    depth++;
    current = cp.delegationManager.getDelegation(current.parentDelegationId);
  }
  return depth;
}

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
  aact <command> [subcommand] [options]

\x1b[1mCORE COMMANDS:\x1b[0m
  \x1b[33mstatus\x1b[0m                                          Display control plane health, mode, and ledger status (§81)
  \x1b[33mmode [get|set <enforcement|observation>]\x1b[0m        Inspect or switch operating mode (§3)
  \x1b[33magent list\x1b[0m                                      List registered AI agents and active statuses (§7, §89)
  \x1b[33magent inspect <agentId>\x1b[0m                         Inspect detailed identity, delegation, and risk profile
  \x1b[33magent capabilities <agentId>\x1b[0m                    List permitted capabilities and effective constraints
  \x1b[33mdelegation list\x1b[0m                                 List all active delegations and hierarchy (§8)
  \x1b[33mdelegation inspect <delegationId>\x1b[0m               Inspect delegation envelope, limits, and parent chain
  \x1b[33mauth check <agentId> <tool> <res> [--amount <amt>]\x1b[0m     Simulate runtime authorization decision (§11, §81)
  \x1b[33mpolicy test <policyFile>\x1b[0m                        Parse declarative Policy DSL file and run validation (§50, §51)
  \x1b[33mpolicy simulate <policyFile>\x1b[0m                    Replay candidate policy over historical audit logs (§52)
  \x1b[33mblast-radius <agentId>\x1b[0m                          Compute compromise reachability & max financial exposure (§38, §84)
  \x1b[33mattack-path <agentId>\x1b[0m                           Analyze lateral movement paths and reachable targets
  \x1b[33maction explain <actionId>\x1b[0m                       Generate AI explanation of authorization decision (§18, §116)
  \x1b[33maudit verify\x1b[0m                                    Verify cryptographic Merkle ledger unbroken hash chain (§25, §65)
  \x1b[33mquarantine <agentId>\x1b[0m                            Emergency kill-switch quarantine for compromised agent (§32, §33)
  \x1b[33mhelp\x1b[0m                                            Display this help guide
`);
}

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printUsage();
    process.exit(0);
  }

  // Initialize in-process Control Plane kernel for local CLI execution
  const cp = new ChronicleControlPlane();
  const ai = new AIPolicyAssistant();

  switch (command) {
    case 'status': {
      printBanner();
      const status = cp.getStatus();
      console.log('\x1b[1mCHRONICLE CONTROL PLANE STATUS (§81):\x1b[0m\n');
      console.log(`Status:              \x1b[32m${status.status.toUpperCase()}\x1b[0m`);
      console.log(`Operating Mode:      \x1b[36m${cp.getMode().toUpperCase()}\x1b[0m`);
      console.log(`Kill Switch Active:  ${status.killSwitchActive ? '\x1b[31mACTIVE (GLOBAL LOCKDOWN)\x1b[0m' : '\x1b[32mINACTIVE (OPERATIONAL)\x1b[0m'}`);
      console.log(`Actions Processed:   ${status.totalActions}`);
      console.log(`Audit Receipts:      ${status.auditReceiptsCount} blocks`);
      console.log(`Ledger Integrity:    ${status.ledgerIntegrity.valid ? '\x1b[32m100% UNBROKEN\x1b[0m' : '\x1b[31mTAMPER DETECTED\x1b[0m'}`);
      console.log(`Active Delegations:  ${status.activeDelegations}`);
      console.log(`Registered Agents:   ${status.registeredAgents}`);
      console.log(`Pending Approvals:   ${status.pendingApprovals}`);
      console.log(`Uptime:              ${Math.floor(status.uptimeSeconds)}s`);
      break;
    }

    case 'mode': {
      if (!subCommand || subCommand === 'get') {
        console.log(`Current Operating Mode: \x1b[36m\x1b[1m${cp.getMode().toUpperCase()}\x1b[0m`);
      } else if (subCommand === 'set') {
        const targetMode = args[2]?.toLowerCase();
        if (targetMode !== 'enforcement' && targetMode !== 'observation') {
          console.error("Usage: aact mode set <enforcement|observation>");
          process.exit(1);
        }
        cp.setMode(targetMode);
        console.log(`\x1b[32m✔ Control Plane switched to ${targetMode.toUpperCase()} mode.\x1b[0m`);
      } else {
        console.log("Usage: aact mode [get|set <enforcement|observation>]");
      }
      break;
    }

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
      } else if (subCommand === 'capabilities') {
        const agentId = args[2];
        if (!agentId) {
          console.error('Usage: aact agent capabilities <agentId>');
          process.exit(1);
        }
        const agent = cp.delegationManager.getAgent(agentId);
        if (!agent) {
          console.error(`Error: Agent '${agentId}' not found.`);
          process.exit(1);
        }
        const delegations = cp.delegationManager.listDelegations().filter(d => d.delegateeId === agentId && !d.revoked);
        printBanner();
        console.log(`\x1b[1mAGENT CAPABILITY PROFILE: ${agent.name} (${agentId})\x1b[0m\n`);
        console.log(`Risk Class:          ${agent.riskClass}`);
        console.log(`Declared Model:      ${agent.modelProvider}`);
        console.log(`Allowed Capabilities: ${agent.allowedCapabilities.join(', ')}`);
        console.log(`\nActive Delegations (${delegations.length}):`);
        for (const d of delegations) {
          console.log(`  • [${d.delegationId}] ${d.purpose}`);
          console.log(`    Tools:    ${d.constraints.allowedTools.join(', ')}`);
          console.log(`    Ceiling:  $${d.constraints.cumulativeValueLimit || 'unlimited'}`);
          console.log(`    Expires:  ${d.expiresAt}`);
        }
      } else {
        printUsage();
      }
      break;
    }

    case 'delegation': {
      if (subCommand === 'list') {
        printBanner();
        console.log('\x1b[1mACTIVE DELEGATION GRAPH (§8, §89):\x1b[0m\n');
        const delegations = cp.delegationManager.listDelegations();
        console.log('┌────────────────────────────┬────────────────────────────┬────────────────────────────┬──────────┐');
        console.log('│ Delegation ID              │ Delegator                  │ Delegatee                  │ Status   │');
        console.log('├────────────────────────────┼────────────────────────────┼────────────────────────────┼──────────┤');
        for (const d of delegations) {
          const id = d.delegationId.padEnd(26);
          const dr = d.delegatorId.padEnd(26);
          const de = d.delegateeId.padEnd(26);
          const st = (d.revoked ? 'REVOKED' : 'ACTIVE').padEnd(8);
          console.log(`│ ${id} │ ${dr} │ ${de} │ ${st} │`);
        }
        console.log('└────────────────────────────┴────────────────────────────┴────────────────────────────┴──────────┘');
      } else if (subCommand === 'inspect') {
        const delegationId = args[2];
        if (!delegationId) {
          console.error('Usage: aact delegation inspect <delegationId>');
          process.exit(1);
        }
        const del = cp.delegationManager.getDelegation(delegationId);
        if (!del) {
          console.error(`Error: Delegation '${delegationId}' not found.`);
          process.exit(1);
        }
        printBanner();
        console.log(`\x1b[1mDELEGATION ENVELOPE: ${del.delegationId} (§8)\x1b[0m\n`);
        console.log(`Purpose:           ${del.purpose}`);
        console.log(`Delegator:         ${del.delegatorId}`);
        console.log(`Delegatee:         ${del.delegateeId}`);
        console.log(`Parent Delegation: ${del.parentDelegationId || 'ROOT (None)'}`);
        console.log(`Depth:             ${computeDelegationDepth(cp, del.delegationId)}`);
        console.log(`Status:            ${del.revoked ? '\x1b[31mREVOKED\x1b[0m' : '\x1b[32mACTIVE\x1b[0m'}`);
        console.log(`Allowed Tools:     ${del.constraints.allowedTools.join(', ')}`);
        console.log(`Resource Patterns: ${del.constraints.resourcePatterns.join(', ')}`);
        console.log(`Max Cumulative:    $${del.constraints.cumulativeValueLimit || 'unlimited'}`);
        console.log(`Expires At:        ${del.expiresAt}`);
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

    case 'policy': {
      if (subCommand === 'test') {
        const filePath = args[2];
        if (!filePath) {
          console.error('Usage: aact policy test <policyFile>');
          process.exit(1);
        }
        const fullPath = resolve(process.cwd(), filePath);
        if (!existsSync(fullPath)) {
          console.error(`Error: Policy file not found: ${fullPath}`);
          process.exit(1);
        }
        const content = readFileSync(fullPath, 'utf8');
        try {
          const ast = parsePolicyDSL(content);
          printBanner();
          console.log(`\x1b[1mPOLICY DSL PARSER REPORT: ${ast.name} (${ast.policyId})\x1b[0m\n`);
          console.log(`Target Action:  ${ast.targetAction}`);
          console.log(`Effect:         ${ast.effect}`);
          console.log(`Conditions (${ast.conditions.length}):`);
          for (const c of ast.conditions) {
            console.log(`  • ${c.negated ? 'NOT ' : ''}${c.field} ${c.operator} ${JSON.stringify(c.value)} [${c.connector || 'AND'}]`);
          }
          if (ast.requireApprovalAbove) {
            console.log(`Approval Cap:   $${ast.requireApprovalAbove}`);
          }
          console.log('\n\x1b[32m✔ Policy syntax is 100% valid PolicyAST.\x1b[0m');
        } catch (err: unknown) {
          console.error(`\x1b[31m✘ Policy syntax error: ${(err as Error).message}\x1b[0m`);
          process.exit(1);
        }
      } else if (subCommand === 'simulate') {
        const filePath = args[2];
        if (!filePath) {
          console.error('Usage: aact policy simulate <policyFile>');
          process.exit(1);
        }
        const fullPath = resolve(process.cwd(), filePath);
        if (!existsSync(fullPath)) {
          console.error(`Error: Policy file not found: ${fullPath}`);
          process.exit(1);
        }
        const content = readFileSync(fullPath, 'utf8');
        const ast = parsePolicyDSL(content);

        const receipts = cp.auditLedger.getReceipts();
        const history = receipts.map(r => ({
          actionId: r.actionId, sessionId: 's', taskId: 't', agentId: r.agentId,
          actionType: r.actionType, tool: r.actionType, resourceId: r.resourceId,
          parameters: { amount: r.riskScore * 10 }, decision: r.decision, timestamp: r.timestamp
        }));

        const simResult = cp.policyEngine.simulatePolicy({ tenantId: 'tenant_acme', proposedPolicyContent: content }, history);
        printBanner();
        console.log(`\x1b[1mPOLICY HISTORICAL REPLAY SIMULATION REPORT (§52)\x1b[0m\n`);
        console.log(`Total Actions Replayed:  ${simResult.totalEvaluated}`);
        console.log(`Newly Allowed Actions:   \x1b[32m${simResult.newlyAllowedCount}\x1b[0m`);
        console.log(`Newly Denied Actions:    \x1b[31m${simResult.newlyDeniedCount}\x1b[0m`);
        console.log(`Newly Held Actions:      \x1b[33m${simResult.newlyHeldCount}\x1b[0m`);
        console.log(`Net Risk Delta:          ${simResult.newlyDeniedCount - simResult.newlyAllowedCount}`);
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

    case 'attack-path': {
      const agentId = args[1];
      if (!agentId) {
        console.error('Usage: aact attack-path <agentId>');
        process.exit(1);
      }
      const attackPaths = cp.blastRadiusAnalyzer.computeAttackPaths(agentId);
      printBanner();
      console.log(`\x1b[1mATTACK PATH ANALYSIS: ${agentId} (§38, §79)\x1b[0m\n`);
      console.log(`Reachable Targets (${attackPaths.length}):`);
      for (const p of attackPaths) {
        console.log(`  • ${p.sourceAgent} ➔ [via delegation ${p.delegationHop}] ➔ ${p.targetResource}`);
        console.log(`    Tool: ${p.tool} | Risk: ${p.riskLevel}`);
      }
      break;
    }

    case 'action': {
      if (subCommand === 'explain') {
        const actionId = args[2];
        if (!actionId) {
          console.error('Usage: aact action explain <actionId>');
          process.exit(1);
        }
        // In local CLI, generate explanation via AI Policy Assistant
        const receipts = cp.auditLedger.getReceipts();
        const receipt = receipts.find(r => r.actionId === actionId) || receipts[0];
        if (!receipt) {
          console.error(`Error: Action '${actionId}' not found.`);
          process.exit(1);
        }
        printBanner();
        console.log(`\x1b[1mAI DECISION EXPLANATION: Action ${receipt.actionId} (§18, §116)\x1b[0m\n`);
        const explanation = ai.explainDecision({
          actionId: receipt.actionId,
          decision: receipt.decision,
          riskScore: receipt.riskScore,
          riskClass: receipt.riskScore > 75 ? 'CRITICAL' : receipt.riskScore > 50 ? 'HIGH' : 'LOW',
          reasonCodes: [receipt.decision === 'ALLOW' ? 'POLICY_PERMIT' : 'POLICY_DENY'],
          explanation: `Action on resource ${receipt.resourceId} evaluated with Merkle hash ${receipt.receiptHash.slice(0, 16)}...`,
          policyVersion: receipt.policyVersion,
          evaluatedAt: receipt.timestamp,
          latencyMs: 0.8
        });
        console.log(explanation);
      } else {
        printUsage();
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
