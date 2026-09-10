/**
 * Chronicle Declarative Policy DSL Engine (§22, §50, §51, §52, §53)
 * Human-Readable Policy Language Parser, AST Compiler, and Test Runner.
 */

import type {
  ActionRequest,
  ActionContext,
  DecisionEffect,
  ReasonCode,
  PolicyAST,
  PolicyTestCase,
  PolicyTestReport,
  ActionHistoryRecord,
} from '@chronicle/core-types';

export interface Token {
  type:
    | 'KEYWORD'
    | 'IDENTIFIER'
    | 'OPERATOR'
    | 'NUMBER'
    | 'STRING'
    | 'LBRACKET'
    | 'RBRACKET'
    | 'COMMA'
    | 'EOF';
  value: string;
  line: number;
}

/**
 * 1. Lexer / Tokenizer for Policy DSL
 */
export function tokenizePolicyDSL(source: string): Token[] {
  const tokens: Token[] = [];
  const lines = source.split(/\r?\n/);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    let line = lines[lineIdx].trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) {
      continue; // Skip comments and empty lines
    }

    let i = 0;
    while (i < line.length) {
      const char = line[i];

      // Whitespace
      if (/\s/.test(char)) {
        i++;
        continue;
      }

      // Strings ('...' or "...")
      if (char === '"' || char === "'") {
        const quote = char;
        let strVal = '';
        i++;
        while (i < line.length && line[i] !== quote) {
          strVal += line[i];
          i++;
        }
        i++; // skip closing quote
        tokens.push({ type: 'STRING', value: strVal, line: lineIdx + 1 });
        continue;
      }

      // Numbers
      if (/\d/.test(char)) {
        let numStr = '';
        while (i < line.length && /[\d.]/.test(line[i])) {
          numStr += line[i];
          i++;
        }
        tokens.push({ type: 'NUMBER', value: numStr, line: lineIdx + 1 });
        continue;
      }

      // Operators (==, !=, <=, >=, <, >)
      if (line.slice(i, i + 2) === '==' || line.slice(i, i + 2) === '!=' ||
          line.slice(i, i + 2) === '<=' || line.slice(i, i + 2) === '>=') {
        tokens.push({ type: 'OPERATOR', value: line.slice(i, i + 2), line: lineIdx + 1 });
        i += 2;
        continue;
      }
      if (char === '<' || char === '>') {
        tokens.push({ type: 'OPERATOR', value: char, line: lineIdx + 1 });
        i++;
        continue;
      }

      // Delimiters
      if (char === '[') {
        tokens.push({ type: 'LBRACKET', value: '[', line: lineIdx + 1 });
        i++;
        continue;
      }
      if (char === ']') {
        tokens.push({ type: 'RBRACKET', value: ']', line: lineIdx + 1 });
        i++;
        continue;
      }
      if (char === ',') {
        tokens.push({ type: 'COMMA', value: ',', line: lineIdx + 1 });
        i++;
        continue;
      }

      // Words (Keywords or Identifiers)
      if (/[a-zA-Z_]/.test(char)) {
        let word = '';
        while (i < line.length && /[a-zA-Z0-9_.]/.test(line[i])) {
          word += line[i];
          i++;
        }

        const upper = word.toUpperCase();
        if (
          [
            'POLICY',
            'ALLOW',
            'DENY',
            'HOLD',
            'WHEN',
            'AND',
            'OR',
            'NOT',
            'IN',
            'NOT_IN',
            'CONTAINS',
            'REQUIRE_APPROVAL_ABOVE',
            'EXPLANATION',
          ].includes(upper)
        ) {
          tokens.push({ type: 'KEYWORD', value: upper, line: lineIdx + 1 });
        } else {
          tokens.push({ type: 'IDENTIFIER', value: word, line: lineIdx + 1 });
        }
        continue;
      }

      i++; // Skip unrecognized character safely
    }
  }

  tokens.push({ type: 'EOF', value: '', line: lines.length });
  return tokens;
}

/**
 * 2. Parser: Transforms Tokens into PolicyAST
 */
export function parsePolicyDSL(source: string): PolicyAST {
  const tokens = tokenizePolicyDSL(source);
  let pos = 0;

  function peek(): Token {
    return tokens[pos] || { type: 'EOF', value: '', line: 0 };
  }

  function consume(expectedType?: string, expectedValue?: string): Token {
    const current = peek();
    if (expectedType && current.type !== expectedType) {
      throw new Error(
        `Parser error at line ${current.line}: Expected token type '${expectedType}', got '${current.type}' (${current.value})`
      );
    }
    if (expectedValue && current.value !== expectedValue) {
      throw new Error(
        `Parser error at line ${current.line}: Expected '${expectedValue}', got '${current.value}'`
      );
    }
    pos++;
    return current;
  }

  let policyId = 'policy_' + Math.random().toString(36).substring(2, 8);
  let policyName = 'Unnamed Policy';

  // Optional: POLICY <name>
  if (peek().type === 'KEYWORD' && peek().value === 'POLICY') {
    consume('KEYWORD', 'POLICY');
    const nameToken = consume();
    policyId = nameToken.value;
    policyName = nameToken.value;
  }

  // Effect: ALLOW | DENY | HOLD
  const effectToken = consume('KEYWORD');
  if (!['ALLOW', 'DENY', 'HOLD'].includes(effectToken.value)) {
    throw new Error(`Expected ALLOW, DENY, or HOLD, got '${effectToken.value}'`);
  }
  const effect = effectToken.value as DecisionEffect;

  // Target Action: e.g. "stripe_refund" or "refund" or "*"
  const actionToken = consume();
  const targetAction = actionToken.value;

  const conditions: PolicyAST['conditions'] = [];
  let requireApprovalAbove: number | undefined;

  // Optional: WHEN <conditions>
  if (peek().type === 'KEYWORD' && peek().value === 'WHEN') {
    consume('KEYWORD', 'WHEN');

    while (peek().type !== 'EOF' && peek().value !== 'REQUIRE_APPROVAL_ABOVE') {
      // Check for NOT prefix
      let negated = false;
      if (peek().type === 'KEYWORD' && peek().value === 'NOT') {
        consume('KEYWORD', 'NOT');
        negated = true;
      }

      // Parse one condition: <field> <op> <value>
      const fieldToken = consume();
      const opToken = consume();

      let op = opToken.value as PolicyAST['conditions'][0]['operator'];
      if (opToken.type === 'KEYWORD' && (opToken.value === 'IN' || opToken.value === 'NOT_IN' || opToken.value === 'CONTAINS')) {
        op = opToken.value as any;
      }

      let parsedValue: unknown;
      const valToken = peek();

      if (valToken.type === 'LBRACKET') {
        // Array of values: ["INTERNAL", "CONFIDENTIAL"]
        consume('LBRACKET');
        const arr: string[] = [];
        while (peek().type !== 'RBRACKET' && peek().type !== 'EOF') {
          const item = consume();
          arr.push(item.value);
          if (peek().type === 'COMMA') {
            consume('COMMA');
          }
        }
        consume('RBRACKET');
        parsedValue = arr;
      } else if (valToken.type === 'NUMBER') {
        parsedValue = Number(consume('NUMBER').value);
      } else if (valToken.type === 'STRING') {
        parsedValue = consume('STRING').value;
      } else {
        const idToken = consume();
        if (idToken.value === 'true') parsedValue = true;
        else if (idToken.value === 'false') parsedValue = false;
        else parsedValue = idToken.value;
      }

      // Check connector: AND vs OR
      let connector: 'AND' | 'OR' = 'AND';
      if (peek().type === 'KEYWORD' && (peek().value === 'AND' || peek().value === 'OR')) {
        connector = consume('KEYWORD').value as 'AND' | 'OR';
      }

      conditions.push({
        field: fieldToken.value,
        operator: op,
        value: parsedValue,
        connector,
        negated,
      });

      // If next is not a condition or connector, stop condition loop
      if (peek().type === 'EOF' || peek().value === 'REQUIRE_APPROVAL_ABOVE') {
        break;
      }
    }
  }

  // Optional: REQUIRE_APPROVAL_ABOVE <number>
  if (peek().type === 'KEYWORD' && peek().value === 'REQUIRE_APPROVAL_ABOVE') {
    consume('KEYWORD', 'REQUIRE_APPROVAL_ABOVE');
    const numToken = consume('NUMBER');
    requireApprovalAbove = Number(numToken.value);
  }

  return {
    policyId,
    name: policyName,
    targetAction,
    conditions,
    requireApprovalAbove,
    effect,
    rawText: source.trim(),
  };
}

/**
 * 3. Evaluator: Executes compiled PolicyAST against an ActionRequest
 */
export function evaluatePolicyDSL(
  policy: PolicyAST,
  action: ActionRequest,
  context: Partial<ActionContext> = {}
): { effect: DecisionEffect; matched: boolean; reason?: string } {
  // Target action match check
  if (policy.targetAction !== '*' && policy.targetAction !== action.tool && policy.targetAction !== action.actionType) {
    return { effect: 'DENY', matched: false, reason: 'Action does not match policy target' };
  }

  // Resolve dot-path fields
  function resolveField(path: string, condValue?: unknown): unknown {
    if (path === 'amount') return action.parameters?.amount;
    if (path === 'tool') return action.tool;
    if (path === 'actionType') return action.actionType;
    if (path === 'resource.sensitivity') return action.resource.sensitivity;
    if (path === 'resource.environment') return action.resource.environment;
    if (path === 'resource.id') return action.resource.id;
    if (path === 'workflow.state') return context.workflowState || action.parameters?.workflowState;
    if (path === 'agent.risk_class' || path === 'agent.riskClass') return context.agent?.riskClass;
    if (path === 'task.type' || path === 'task.declaredPurpose') return context.task?.declaredPurpose;

    // Sequence check (§47, §48)
    if (path === 'sequence.has_occurred') {
      const history = (context as any)?.history || (context as any)?.previousActions || action.parameters?.__history || [];
      if (Array.isArray(history)) {
        return history.some((h: any) => h.tool === condValue || h.actionType === condValue);
      }
      return false;
    }

    // Check action parameters
    if (path.startsWith('parameters.')) {
      const pKey = path.slice(11);
      return action.parameters?.[pKey];
    }

    return undefined;
  }

  // Evaluate single condition
  function evalSingle(cond: (typeof policy.conditions)[0]): boolean {
    const actual = resolveField(cond.field, cond.value);
    const expected = cond.value;

    let satisfied = false;
    switch (cond.operator) {
      case '==':
        if (cond.field === 'sequence.has_occurred') {
          satisfied = !!actual;
        } else {
          satisfied = String(actual) === String(expected);
        }
        break;
      case '!=':
        satisfied = String(actual) !== String(expected);
        break;
      case '<=':
        satisfied = Number(actual) <= Number(expected);
        break;
      case '>=':
        satisfied = Number(actual) >= Number(expected);
        break;
      case '<':
        satisfied = Number(actual) < Number(expected);
        break;
      case '>':
        satisfied = Number(actual) > Number(expected);
        break;
      case 'IN':
        if (Array.isArray(expected)) {
          satisfied = expected.includes(String(actual));
        }
        break;
      case 'NOT_IN':
        if (Array.isArray(expected)) {
          satisfied = !expected.includes(String(actual));
        }
        break;
      case 'CONTAINS':
        if (Array.isArray(actual)) {
          satisfied = actual.includes(expected);
        } else if (typeof actual === 'string') {
          satisfied = actual.includes(String(expected));
        }
        break;
      default:
        satisfied = false;
    }

    return cond.negated ? !satisfied : satisfied;
  }

  // Evaluate conditions using DNF (Disjunctive Normal Form):
  // Clauses are separated by OR. Each clause contains conditions conjoined by AND.
  if (policy.conditions.length > 0) {
    const clauses: (typeof policy.conditions)[] = [];
    let currentClause: (typeof policy.conditions) = [];

    for (let idx = 0; idx < policy.conditions.length; idx++) {
      const c = policy.conditions[idx];
      currentClause.push(c);
      if (c.connector === 'OR' || idx === policy.conditions.length - 1) {
        clauses.push(currentClause);
        currentClause = [];
      }
    }

    // At least one clause must evaluate to true
    let anyClausePassed = false;
    let failureReason = '';

    for (const clause of clauses) {
      const allInClausePassed = clause.every(c => evalSingle(c));
      if (allInClausePassed) {
        anyClausePassed = true;
        break;
      }
    }

    if (!anyClausePassed) {
      const firstFailed = policy.conditions.find(c => !evalSingle(c));
      const actual = firstFailed ? resolveField(firstFailed.field, firstFailed.value) : undefined;
      return {
        effect: 'DENY',
        matched: false,
        reason: `Condition '${firstFailed?.negated ? 'NOT ' : ''}${firstFailed?.field} ${firstFailed?.operator} ${JSON.stringify(firstFailed?.value)}' not satisfied (actual: ${JSON.stringify(actual)})`,
      };
    }
  }

  // Check REQUIRE_APPROVAL_ABOVE threshold (§20, §35)
  if (policy.requireApprovalAbove !== undefined) {
    const amount = Number(action.parameters?.amount ?? 0);
    if (amount > policy.requireApprovalAbove) {
      return {
        effect: 'HOLD',
        matched: true,
        reason: `Transaction amount $${amount} exceeds approval threshold of $${policy.requireApprovalAbove}`,
      };
    }
  }

  return {
    effect: policy.effect,
    matched: true,
    reason: `Matched policy '${policy.name}'`,
  };
}

/**
 * 4. Policy Test Runner (§51)
 */
export function runPolicyTests(policy: PolicyAST, testCases: PolicyTestCase[]): PolicyTestReport {
  let passed = 0;
  let failed = 0;
  const results: PolicyTestReport['results'] = [];

  for (const test of testCases) {
    const evalResult = evaluatePolicyDSL(policy, test.mockAction, test.mockContext);
    const actualDecision = evalResult.matched ? evalResult.effect : 'DENY';
    const isPass = actualDecision === test.expectedDecision;

    if (isPass) {
      passed++;
    } else {
      failed++;
    }

    results.push({
      testId: test.testId,
      name: test.name,
      passed: isPass,
      actualDecision,
      expectedDecision: test.expectedDecision,
      error: isPass ? undefined : `Expected ${test.expectedDecision} but got ${actualDecision}: ${evalResult.reason}`,
    });
  }

  return {
    totalTests: testCases.length,
    passed,
    failed,
    results,
  };
}

/**
 * 5. Policy Coverage & Regression Analyzer (§52, §53)
 */
export interface PolicyCoverageReport {
  totalHistoricalActions: number;
  explicitlyCoveredActions: number;
  uncoveredDefaultActions: number;
  coveragePercentage: number;
  holdRate: number;
  allowRate: number;
  denyRate: number;
}

export function analyzePolicyCoverage(
  policies: PolicyAST[],
  historicalActions: ActionHistoryRecord[]
): PolicyCoverageReport {
  if (historicalActions.length === 0) {
    return {
      totalHistoricalActions: 0,
      explicitlyCoveredActions: 0,
      uncoveredDefaultActions: 0,
      coveragePercentage: 100,
      holdRate: 0,
      allowRate: 0,
      denyRate: 0,
    };
  }

  let coveredCount = 0;
  let allowCount = 0;
  let holdCount = 0;
  let denyCount = 0;

  for (const hist of historicalActions) {
    const mockReq: ActionRequest = {
      actionId: hist.actionId,
      tenantId: 'tenant_default',
      sessionId: hist.sessionId,
      taskId: hist.taskId,
      agentId: hist.agentId,
      delegationId: 'del_default',
      actionType: hist.actionType,
      tool: hist.tool,
      resource: {
        id: hist.resourceId,
        type: 'resource',
        sensitivity: 'INTERNAL',
        environment: 'production',
      },
      parameters: hist.parameters,
      parametersHash: 'sha256:dummy',
      timestamp: hist.timestamp,
    };

    let matchedPolicy = false;
    const histWorkflowState = (hist.parameters?.workflowState as string) || 'APPROVED';
    for (const p of policies) {
      const res = evaluatePolicyDSL(p, mockReq, { workflowState: histWorkflowState });
      if (res.matched) {
        matchedPolicy = true;
        if (res.effect === 'ALLOW') allowCount++;
        else if (res.effect === 'HOLD') holdCount++;
        else denyCount++;
        break;
      }
    }

    if (matchedPolicy) {
      coveredCount++;
    } else {
      denyCount++; // Default fail-closed (§54)
    }
  }

  return {
    totalHistoricalActions: historicalActions.length,
    explicitlyCoveredActions: coveredCount,
    uncoveredDefaultActions: historicalActions.length - coveredCount,
    coveragePercentage: Math.round((coveredCount / historicalActions.length) * 100),
    allowRate: Math.round((allowCount / historicalActions.length) * 100),
    holdRate: Math.round((holdCount / historicalActions.length) * 100),
    denyRate: Math.round((denyCount / historicalActions.length) * 100),
  };
}

/**
 * 6. Policy Version Regression Comparator (§51, §52)
 */
export function comparePolicyVersions(
  v1: PolicyAST,
  v2: PolicyAST,
  suite: PolicyTestCase[]
): {
  regressions: PolicyTestCase[];
  improvements: PolicyTestCase[];
  unchanged: PolicyTestCase[];
  v1PassRate: number;
  v2PassRate: number;
} {
  const v1Report = runPolicyTests(v1, suite);
  const v2Report = runPolicyTests(v2, suite);

  const regressions: PolicyTestCase[] = [];
  const improvements: PolicyTestCase[] = [];
  const unchanged: PolicyTestCase[] = [];

  for (let i = 0; i < suite.length; i++) {
    const testCase = suite[i];
    const v1Pass = v1Report.results[i]?.passed ?? false;
    const v2Pass = v2Report.results[i]?.passed ?? false;

    if (v1Pass && !v2Pass) {
      regressions.push(testCase);
    } else if (!v1Pass && v2Pass) {
      improvements.push(testCase);
    } else {
      unchanged.push(testCase);
    }
  }

  const v1PassRate = suite.length === 0 ? 100 : Math.round((v1Report.passed / suite.length) * 100);
  const v2PassRate = suite.length === 0 ? 100 : Math.round((v2Report.passed / suite.length) * 100);

  return {
    regressions,
    improvements,
    unchanged,
    v1PassRate,
    v2PassRate,
  };
}

export * from './shadow.ts';

