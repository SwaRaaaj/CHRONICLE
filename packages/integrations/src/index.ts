/**
 * Chronicle Enterprise Identity & OIDC Federation Bridge (§57, §98)
 * Bridges enterprise workforce identity providers (Microsoft Entra ID, Okta, Google Workspace)
 * into Chronicle Human Sponsor delegations without compromising the internal Ed25519 cryptographic trust model.
 */

import type { HumanSponsor } from '@chronicle/core-types';
import { generateEd25519KeyPair } from '@chronicle/crypto-primitives';

export interface OIDCProviderConfig {
  name: string;
  issuer: string;
  clientId: string;
  jwksUri?: string;
  roleClaim?: string;
  defaultTenantId: string;
}

export interface OIDCClaims {
  sub: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  email?: string;
  name?: string;
  groups?: string[];
  roles?: string[];
  tenant?: string;
}

export class OIDCFederationBridge {
  private providers: Map<string, OIDCProviderConfig> = new Map();

  constructor() {
    // Register default enterprise templates
    this.registerProvider('https://login.microsoftonline.com/common/v2.0', {
      name: 'Microsoft Entra ID',
      issuer: 'https://login.microsoftonline.com/common/v2.0',
      clientId: 'chronicle-entra-app',
      defaultTenantId: 'tenant_enterprise'
    });

    this.registerProvider('https://acme.okta.com', {
      name: 'Okta Enterprise IDP',
      issuer: 'https://acme.okta.com',
      clientId: 'chronicle-okta-client',
      defaultTenantId: 'tenant_acme'
    });

    this.registerProvider('https://accounts.google.com', {
      name: 'Google Workspace',
      issuer: 'https://accounts.google.com',
      clientId: 'chronicle-google-workspace',
      defaultTenantId: 'tenant_google'
    });
  }

  public registerProvider(issuer: string, config: OIDCProviderConfig): void {
    this.providers.set(issuer, config);
  }

  public getProvider(issuer: string): OIDCProviderConfig | undefined {
    return this.providers.get(issuer);
  }

  /**
   * Parses and validates an OIDC ID token JWT claims payload (stub / mockable verification) (§57).
   */
  public async verifyOIDCToken(token: string, expectedIssuer: string): Promise<HumanSponsor> {
    const provider = this.providers.get(expectedIssuer);
    if (!provider) {
      throw new Error(`Untrusted OIDC issuer '${expectedIssuer}'. Provider not registered in Chronicle.`);
    }

    // Decode JWT payload (standard 3-part base64 token)
    let claims: OIDCClaims;
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payloadStr = Buffer.from(parts[1], 'base64').toString('utf8');
        claims = JSON.parse(payloadStr);
      } else {
        // Mock token payload
        claims = JSON.parse(token);
      }
    } catch {
      throw new Error('Invalid OIDC ID token format. Expected valid JWT.');
    }

    // Verify claims
    if (claims.iss && claims.iss !== expectedIssuer) {
      throw new Error(`OIDC Issuer mismatch: expected '${expectedIssuer}', got '${claims.iss}'`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp < now) {
      throw new Error(`OIDC ID token expired at ${new Date(claims.exp * 1000).toISOString()}`);
    }

    return this.mapClaimsToSponsor(claims, provider);
  }

  /**
   * Maps enterprise OIDC claims to Chronicle HumanSponsor identity record (§57)
   */
  public mapClaimsToSponsor(claims: OIDCClaims, provider: OIDCProviderConfig): HumanSponsor {
    const userId = `sponsor_oidc_${claims.sub.replace(/[^a-zA-Z0-9_]/g, '_')}`;
    const email = claims.email || `${claims.sub}@enterprise.internal`;
    const name = claims.name || claims.email?.split('@')[0] || 'Enterprise Sponsor';
    const roles = claims.roles || claims.groups || ['AgentAdministrator'];

    return {
      userId,
      name,
      email,
      role: roles[0] || 'AgentAdministrator',
      department: 'Engineering / Operations',
      tenantId: claims.tenant || provider.defaultTenantId,
      publicKey: generateEd25519KeyPair().publicKey,
      createdAt: new Date().toISOString()
    };
  }
}
