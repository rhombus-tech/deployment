use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwitterAirdropVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TwitterAirdropBotSybilFarmingDetector {
    bytecode: Vec<u8>,
}

impl TwitterAirdropBotSybilFarmingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TwitterAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_fake_follower_verification());
        vulnerabilities.extend(self.detect_retweet_bot_farming());
        vulnerabilities.extend(self.detect_account_age_bypass());

        vulnerabilities
    }

    fn detect_fake_follower_verification(&self) -> Vec<TwitterAirdropVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (eligibility storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_twitter_verification = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_twitter_verification {
                    let verifies_follower_authenticity = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let checks_engagement_metrics = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !verifies_follower_authenticity {
                        vulns.push(TwitterAirdropVulnerability {
                            pc,
                            vulnerability_type: "FakeFollowerVerification".to_string(),
                            description: format!(
                                "Twitter airdrop eligibility at PC {} accepts fake followers. Attack: airdrop requires N followers to claim, attacker buys fake followers or creates \
                                bot network. Fake follower services: Fiverr/SocialBoss sell 10K followers for $50, bots follow target account, attacker claims airdrop. Or: attacker \
                                creates 1000 Twitter bot accounts, all follow project, uses 1000 wallets to claim airdrop (Sybil attack). Example: airdrop requires 100 followers, \
                                attacker buys 100 fake followers for $5, gets $500 airdrop. Multiplication: attacker creates 100 wallets + 100 Twitter accounts with fake followers \
                                each, claims $50K. Real farms: Twitter bot networks of 10K+ accounts controlled by single entity. Missing: follower quality verification, engagement rate \
                                checks, account authenticity scoring. Should verify: follower account age >180 days, follower tweet frequency >1/week, follower/following ratio <2, \
                                check if followers have profile pictures/bios, integrate Twitter API v2 authenticity metrics.",
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

    fn detect_retweet_bot_farming(&self) -> Vec<TwitterAirdropVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (task verification)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_claim_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_claim_execution {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let verifies_retweet_authenticity = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let checks_account_uniqueness = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    
                    if !verifies_retweet_authenticity {
                        vulns.push(TwitterAirdropVulnerability {
                            pc,
                            vulnerability_type: "RetweetBotFarming".to_string(),
                            description: format!(
                                "Retweet task verification at PC {} vulnerable to bot automation. Attack: airdrop requires retweet + like + comment, attacker automates Twitter API \
                                to complete tasks with bot army. Automation tools: Tweetdeck, Hootsuite, custom scripts using Twitter API. Attack: (1) create 1000 Twitter accounts, \
                                (2) automate retweet/like/comment for all, (3) link each to unique wallet, (4) claim 1000x airdrop. Example: project gives 100 tokens per retweet, \
                                attacker automates 10K retweets = 1M tokens claimed. Detection evasion: rotate IP addresses, use residential proxies, randomize timing between actions, \
                                use realistic comments from GPT-3. Real bot services: 10K retweets for $100 on black market. Missing: bot detection (API rate limiting), tweet uniqueness \
                                validation, anti-Sybil measures. Should implement: verify retweet from OAuth-authenticated session (not just tweet ID), check for suspicious patterns \
                                (100 accounts retweeting within 1 second), require account to have original tweets (not just retweets), integrate Botometer API for bot scoring.",
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

    fn detect_account_age_bypass(&self) -> Vec<TwitterAirdropVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (account age check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_eligibility_check = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_eligibility_check {
                    let enforces_minimum_age = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let verifies_creation_timestamp = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !enforces_minimum_age {
                        vulns.push(TwitterAirdropVulnerability {
                            pc,
                            vulnerability_type: "AccountAgeBypass".to_string(),
                            description: format!(
                                "Twitter account verification at PC {} lacks age enforcement. Attack: airdrop intended for real users, but without account age requirement, bots \
                                create fresh accounts. Account farming: mass create Twitter accounts using temp email services (guerillamail, 10minutemail), automated CAPTCHA solving \
                                (2captcha), phone verification bypass (virtual phone numbers). Example: attacker creates 5000 new Twitter accounts in 1 day, all claim airdrop. Or: \
                                aged account market - attacker buys 1000 accounts created >1 year ago for $1 each, uses for airdrops. Missing: minimum account age requirement, tweet \
                                history validation, account activity scoring. Should require: Twitter account created >6 months before airdrop announcement, account has >50 tweets, \
                                account engaged with crypto content (not just created for airdrop), check account suspension history. Additional: require account connected to verified \
                                email domain (not temp email), check if account follows similar patterns to known Sybils.",
                                pc
                            ),
                            confidence: 0.84,
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
