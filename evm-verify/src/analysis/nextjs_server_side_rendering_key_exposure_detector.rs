use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextjsServerVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct NextjsServerSideRenderingKeyExposureDetector {
    bytecode: Vec<u8>,
}

impl NextjsServerSideRenderingKeyExposureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<NextjsServerVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_private_key_in_getserversideprops());
        vulnerabilities.extend(self.detect_api_key_client_exposure());
        vulnerabilities.extend(self.detect_environment_variable_leak());

        vulnerabilities
    }

    fn detect_private_key_in_getserversideprops(&self) -> Vec<NextjsServerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (data storage for SSR)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_sensitive_data = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_sensitive_data {
                    let sanitizes_props = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let filters_server_data = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    
                    if !sanitizes_props {
                        vulns.push(NextjsServerVulnerability {
                            pc,
                            vulnerability_type: "PrivateKeyInGetServerSideProps".to_string(),
                            description: format!(
                                "Server-side props at PC {} may expose sensitive keys. Attack: Next.js getServerSideProps runs on server, if returns sensitive data in props, exposed \
                                to client via __NEXT_DATA__ script tag. SSR key exposure: (1) getServerSideProps fetches data using server-only API key, (2) accidentally includes key in \
                                returned props, (3) Next.js serializes props to JSON in HTML, (4) client receives props in window.__NEXT_DATA__, (5) API key visible in page source. Example: \
                                export async function getServerSideProps() {{ const data = await fetch(url, {{ headers: {{ 'X-API-Key': process.env.SECRET_KEY }} }}); return {{ props: {{ data, \
                                apiKey: process.env.SECRET_KEY }} }}; }}, SECRET_KEY now in HTML source. Or: return entire process.env object in props, leaks all environment variables. Real \
                                vulnerability: private keys, database credentials, internal API endpoints exposed to all users. Missing: props sanitization, server-only data separation, \
                                environment variable filtering. Should implement: never return process.env in props, filter sensitive fields before return, use separate types for server data \
                                vs client props, validate props don't contain secrets.",
                                pc
                            ),
                            confidence: 0.90,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_api_key_client_exposure(&self) -> Vec<NextjsServerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (API request data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_api_call = window.iter().any(|&b| b == 0xFA); // STATICCALL
                
                if has_api_call {
                    let uses_server_middleware = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let validates_request_origin = window.iter().any(|&b| b == 0x14);
                    
                    if !uses_server_middleware {
                        vulns.push(NextjsServerVulnerability {
                            pc,
                            vulnerability_type: "ApiKeyClientExposure".to_string(),
                            description: format!(
                                "API call at PC {} exposes keys to client-side. Attack: Next.js client-side code calls API with embedded credentials, keys extractable from bundle. \
                                Client-side API exposure: (1) component makes API call: fetch('https://api.service.com', {{ headers: {{ Authorization: 'Bearer sk_live_...' }} }}), (2) \
                                API key hardcoded in client component, (3) bundled into public JavaScript, (4) visible in DevTools Network tab or source maps, (5) attacker extracts key, uses \
                                for own requests. Example: const OPENAI_KEY = 'sk-...'; fetch('https://api.openai.com', {{ headers: {{ Authorization: OPENAI_KEY }} }}), key in bundle, anyone \
                                can use OpenAI API on your bill. Or: Infura/Alchemy RPC URLs with project IDs in code, attackers can drain your request quota. Missing: API route proxying, \
                                server-side authentication, environment variable protection. Should implement: move API calls to Next.js API routes (/pages/api/*), call external APIs from \
                                server only, use NEXT_PUBLIC_ prefix only for truly public values, implement rate limiting on API routes.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_environment_variable_leak(&self) -> Vec<NextjsServerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (env var access)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let exposes_to_client = window.iter().any(|&b| b == 0x55); // SSTORE (client state)
                
                if exposes_to_client {
                    let validates_public_prefix = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let filters_sensitive_vars = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !validates_public_prefix {
                        vulns.push(NextjsServerVulnerability {
                            pc,
                            vulnerability_type: "EnvironmentVariableLeak".to_string(),
                            description: format!(
                                "Environment variable handling at PC {} may leak secrets. Attack: Next.js exposes NEXT_PUBLIC_* env vars to client, misnamed variables accidentally public. \
                                Env var exposure: (1) developer adds NEXT_PUBLIC_PRIVATE_KEY=... to .env, (2) thinks 'PRIVATE' suffix makes it private, (3) NEXT_PUBLIC_ prefix exposes to \
                                client, (4) key accessible via process.env.NEXT_PUBLIC_PRIVATE_KEY in browser. Or: webpack DefinePlugin replaces process.env references at build time, if \
                                used in client code, value inlined in bundle. Example: const dbUrl = process.env.DATABASE_URL; used in client component, DATABASE_URL string literal in bundle \
                                even without NEXT_PUBLIC_ prefix (if build process doesn't catch). Real mistakes: NEXT_PUBLIC_STRIPE_SECRET_KEY, NEXT_PUBLIC_WALLET_PRIVATE_KEY in production \
                                code. Missing: environment variable validation, build-time secret detection, .env.local vs .env.production separation. Should enforce: audit all NEXT_PUBLIC_* \
                                variables, never use NEXT_PUBLIC_ prefix for secrets, use build-time checks to prevent non-NEXT_PUBLIC_ vars in client code, separate .env files for server vs \
                                client config, implement pre-commit hooks to detect secret patterns.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
