        // Celer Bridge SGN
        let celer_detector = CelerBridgeSgnDetector::new(self.bytecode.clone());
        let celer_findings = celer_detector.detect();
        modules_run += 1;

        // Axelar GMP Security
        let axelar_detector = AxelarGmpSecurityDetector::new(self.bytecode.clone());
        let axelar_findings = axelar_detector.detect();
        modules_run += 1;

        // Allbridge Liquidity
        let allbridge_detector = AllbridgeLiquidityDetector::new(self.bytecode.clone());
        let allbridge_findings = allbridge_detector.detect();
        modules_run += 1;

        // Synapse Bridge Swap
        let synapse_detector = SynapseBridgeSwapDetector::new(self.bytecode.clone());
        let synapse_findings = synapse_detector.detect();
        modules_run += 1;

        // Connext Amarok Router
        let connext_detector = ConnextAmarokRouterDetector::new(self.bytecode.clone());
        let connext_findings = connext_detector.detect();
        modules_run += 1;

        // deBridge DLN Security
        let debridge_detector = DlnDebridgeSecurityDetector::new(self.bytecode.clone());
        let debridge_findings = debridge_detector.detect();
        modules_run += 1;

        // GMX Price Impact
        let gmx_detector = GmxPriceImpactDetector::new(self.bytecode.clone());
        let gmx_findings = gmx_detector.detect();
        modules_run += 1;

        // Synthetix Debt Pool
        let synthetix_detector = SynthetixDebtPoolDetector::new(self.bytecode.clone());
        let synthetix_findings = synthetix_detector.detect();
        modules_run += 1;

        // === BATCH 6: 42 MISSING DETECTORS FROM EARLY BATCHES ===
        use crate::analysis::{
            integer_overflow_unchecked_detector::IntegerOverflowUncheckedDetector,
            integer_underflow_unchecked_detector::IntegerUnderflowUncheckedDetector,
            returndata_overflow_detector::ReturndataOverflowDetector,
            calldata_validation_bypass_detector::CalldataValidationBypassDetector,
            array_bounds_overflow_detector::ArrayBoundsOverflowDetector,
            return_value_unchecked_detector::ReturnValueUncheckedDetector,
            send_vs_transfer_vulnerability_detector::SendVsTransferVulnerabilityDetector,
            address_zero_validation_detector::AddressZeroValidationDetector,
            infinite_approval_exploit_detector::InfiniteApprovalExploitDetector,
            nft_ownership_validation_detector::NftOwnershipValidationDetector,
            nft_approval_hijack_detector::NftApprovalHijackDetector,
            nft_royalty_bypass_detector::NftRoyaltyBypassDetector,
            griefing_attack_detector::GriefingAttackDetector,
            denial_of_service_detector::DenialOfServiceDetector,
            flash_swap_exploit_detector::FlashSwapExploitDetector,
            first_depositor_inflation_detector::FirstDepositorInflationDetector,
            slippage_manipulation_detector::SlippageManipulationDetector,
            poly_network_2021_detector::PolyNetwork2021Detector,
            ronin_bridge_2022_detector::RoninBridge2022Detector,
            nomad_bridge_2022_detector::NomadBridge2022Detector,
            wormhole_bridge_2022_detector::WormholeBridge2022Detector,
            euler_finance_2023_detector::EulerFinance2023Detector,
            flash_loan_arbitrage_detector::FlashLoanArbitrageDetector,
            kyberswap_2023_detector::Kyberswap2023Detector,
            erc721_unsafe_transfer_detector::Erc721UnsafeTransferDetector,
            erc1155_double_transfer_detector::Erc1155DoubleTransferDetector,
            erc4626_sandwich_detector::Erc4626SandwichDetector,
            uniswap_v3_manipulation_detector::UniswapV3ManipulationDetector,
            curve_reentrancy_detector::CurveReentrancyDetector,
            transparent_proxy_collision_detector::TransparentProxyCollisionDetector,
            uups_uninitialized_detector::UupsUninitializedDetector,
            beacon_proxy_upgrade_detector::BeaconProxyUpgradeDetector,
            chainlink_oracle_stale_detector::ChainlinkOracleStaleDetector,
            optimism_l2_sequencer_detector::OptimismL2SequencerDetector,
            arbitrum_nitro_gas_detector::ArbitrumNitroGasDetector,
            zkrollup_state_transition_detector::ZkrollupStateTransitionDetector,
            governance_vote_manipulation_detector::GovernanceVoteManipulationDetector,
            merkle_proof_forgery_detector::MerkleProofForgeryDetector,
            balancer_v2_vault_manipulation_detector::BalancerV2VaultManipulationDetector,
            compound_v3_position_detector::CompoundV3PositionDetector,
            maker_dao_liquidation_detector::MakerDaoLiquidationDetector,
            lido_steth_peg_detector::LidoStethPegDetector,
        };

        // Core Vulnerabilities (9)
        let int_overflow_detector = IntegerOverflowUncheckedDetector::new(self.bytecode.clone());
        let _int_overflow_findings = int_overflow_detector.detect();
        modules_run += 1;

        let int_underflow_detector = IntegerUnderflowUncheckedDetector::new(self.bytecode.clone());
        let _int_underflow_findings = int_underflow_detector.detect();
        modules_run += 1;

        let returndata_detector = ReturndataOverflowDetector::new(self.bytecode.clone());
        let _returndata_findings = returndata_detector.detect();
        modules_run += 1;

        let calldata_detector = CalldataValidationBypassDetector::new(self.bytecode.clone());
        let _calldata_findings = calldata_detector.detect();
        modules_run += 1;

        let array_bounds_detector = ArrayBoundsOverflowDetector::new(self.bytecode.clone());
        let _array_bounds_findings = array_bounds_detector.detect();
        modules_run += 1;

        let return_value_detector = ReturnValueUncheckedDetector::new(self.bytecode.clone());
        let _return_value_findings = return_value_detector.detect();
        modules_run += 1;

        let send_transfer_detector = SendVsTransferVulnerabilityDetector::new(self.bytecode.clone());
        let _send_transfer_findings = send_transfer_detector.detect();
        modules_run += 1;

        let addr_zero_detector = AddressZeroValidationDetector::new(self.bytecode.clone());
        let _addr_zero_findings = addr_zero_detector.detect();
        modules_run += 1;

        let infinite_approval_detector = InfiniteApprovalExploitDetector::new(self.bytecode.clone());
        let _infinite_approval_findings = infinite_approval_detector.detect();
        modules_run += 1;

        // NFT & DeFi (8)
        let nft_ownership_detector = NftOwnershipValidationDetector::new(self.bytecode.clone());
        let _nft_ownership_findings = nft_ownership_detector.detect();
        modules_run += 1;

        let nft_approval_detector = NftApprovalHijackDetector::new(self.bytecode.clone());
        let _nft_approval_findings = nft_approval_detector.detect();
        modules_run += 1;

        let nft_royalty_detector = NftRoyaltyBypassDetector::new(self.bytecode.clone());
        let _nft_royalty_findings = nft_royalty_detector.detect();
        modules_run += 1;

        let griefing_detector = GriefingAttackDetector::new(self.bytecode.clone());
        let _griefing_findings = griefing_detector.detect();
        modules_run += 1;

        let dos_detector = DenialOfServiceDetector::new(self.bytecode.clone());
        let _dos_findings = dos_detector.detect();
        modules_run += 1;

        let flash_swap_detector = FlashSwapExploitDetector::new(self.bytecode.clone());
        let _flash_swap_findings = flash_swap_detector.detect();
        modules_run += 1;

        let first_depositor_detector = FirstDepositorInflationDetector::new(self.bytecode.clone());
        let _first_depositor_findings = first_depositor_detector.detect();
        modules_run += 1;

        let slippage_manip_detector = SlippageManipulationDetector::new(self.bytecode.clone());
        let _slippage_manip_findings = slippage_manip_detector.detect();
        modules_run += 1;

        // Major Exploits (7)
        let poly_detector = PolyNetwork2021Detector::new(self.bytecode.clone());
        let _poly_findings = poly_detector.detect();
        modules_run += 1;

        let ronin_detector = RoninBridge2022Detector::new(self.bytecode.clone());
        let _ronin_findings = ronin_detector.detect();
        modules_run += 1;

        let nomad_detector = NomadBridge2022Detector::new(self.bytecode.clone());
        let _nomad_findings = nomad_detector.detect();
        modules_run += 1;

        let wormhole_detector = WormholeBridge2022Detector::new(self.bytecode.clone());
        let _wormhole_findings = wormhole_detector.detect();
        modules_run += 1;

        let euler_detector = EulerFinance2023Detector::new(self.bytecode.clone());
        let _euler_findings = euler_detector.detect();
        modules_run += 1;

        let flash_loan_arb_detector = FlashLoanArbitrageDetector::new(self.bytecode.clone());
        let _flash_loan_arb_findings = flash_loan_arb_detector.detect();
        modules_run += 1;

        let kyberswap_detector = Kyberswap2023Detector::new(self.bytecode.clone());
        let _kyberswap_findings = kyberswap_detector.detect();
        modules_run += 1;

        // ERC Standards & Protocols (8)
        let erc721_detector = Erc721UnsafeTransferDetector::new(self.bytecode.clone());
        let _erc721_findings = erc721_detector.detect();
        modules_run += 1;

        let erc1155_detector = Erc1155DoubleTransferDetector::new(self.bytecode.clone());
        let _erc1155_findings = erc1155_detector.detect();
        modules_run += 1;

        let erc4626_detector = Erc4626SandwichDetector::new(self.bytecode.clone());
        let _erc4626_findings = erc4626_detector.detect();
        modules_run += 1;

        let uniswap_v3_detector = UniswapV3ManipulationDetector::new(self.bytecode.clone());
        let _uniswap_v3_findings = uniswap_v3_detector.detect();
        modules_run += 1;

        let curve_detector = CurveReentrancyDetector::new(self.bytecode.clone());
        let _curve_findings = curve_detector.detect();
        modules_run += 1;

        let transparent_proxy_detector = TransparentProxyCollisionDetector::new(self.bytecode.clone());
        let _transparent_proxy_findings = transparent_proxy_detector.detect();
        modules_run += 1;

        let uups_detector = UupsUninitializedDetector::new(self.bytecode.clone());
        let _uups_findings = uups_detector.detect();
        modules_run += 1;

        let beacon_proxy_detector = BeaconProxyUpgradeDetector::new(self.bytecode.clone());
        let _beacon_proxy_findings = beacon_proxy_detector.detect();
        modules_run += 1;

        // Oracle & L2 (10)
        let chainlink_detector = ChainlinkOracleStaleDetector::new(self.bytecode.clone());
        let _chainlink_findings = chainlink_detector.detect();
        modules_run += 1;

        let optimism_detector = OptimismL2SequencerDetector::new(self.bytecode.clone());
        let _optimism_findings = optimism_detector.detect();
        modules_run += 1;

        let arbitrum_detector = ArbitrumNitroGasDetector::new(self.bytecode.clone());
        let _arbitrum_findings = arbitrum_detector.detect();
        modules_run += 1;

        let zkrollup_detector = ZkrollupStateTransitionDetector::new(self.bytecode.clone());
        let _zkrollup_findings = zkrollup_detector.detect();
        modules_run += 1;

        let gov_vote_detector = GovernanceVoteManipulationDetector::new(self.bytecode.clone());
        let _gov_vote_findings = gov_vote_detector.detect();
        modules_run += 1;

        let merkle_detector = MerkleProofForgeryDetector::new(self.bytecode.clone());
        let _merkle_findings = merkle_detector.detect();
        modules_run += 1;

        let balancer_v2_detector = BalancerV2VaultManipulationDetector::new(self.bytecode.clone());
        let _balancer_v2_findings = balancer_v2_detector.detect();
        modules_run += 1;

        let compound_v3_detector = CompoundV3PositionDetector::new(self.bytecode.clone());
        let _compound_v3_findings = compound_v3_detector.detect();
        modules_run += 1;

        let maker_detector = MakerDaoLiquidationDetector::new(self.bytecode.clone());
        let _maker_findings = maker_detector.detect();
        modules_run += 1;

        let lido_detector = LidoStethPegDetector::new(self.bytecode.clone());
        let _lido_findings = lido_detector.detect();
        modules_run += 1;

        // === MISSING DETECTORS - ORACLE/BRIDGE/MEV/CROSS-CHAIN (19 NEW - DEC 2025) ===
        let oracle_sandwich_detector = OracleSandwichDetector::new(self.bytecode.clone());
        let _oracle_sandwich_findings = oracle_sandwich_detector.detect();
        modules_run += 1;

        let oracle_deviation_detector = OracleDeviationDetector::new(self.bytecode.clone());
        let _oracle_deviation_findings = oracle_deviation_detector.detect();
        modules_run += 1;

        let oracle_free_option_detector = OracleFreeOptionDetector::new(self.bytecode.clone());
        let _oracle_free_option_findings = oracle_free_option_detector.detect();
        modules_run += 1;

        let oracle_griefing_detector = OracleGriefingDetector::new(self.bytecode.clone());
        let _oracle_griefing_findings = oracle_griefing_detector.detect();
        modules_run += 1;

        let price_feed_poisoning_detector = PriceFeedPoisoningDetector::new(self.bytecode.clone());
        let _price_feed_poisoning_findings = price_feed_poisoning_detector.detect();
        modules_run += 1;

        let chainlink_round_manipulation_detector = ChainlinkRoundManipulationDetector::new(self.bytecode.clone());
        let _chainlink_round_manipulation_findings = chainlink_round_manipulation_detector.detect();
        modules_run += 1;

        let cross_chain_finality_detector = CrossChainFinalityDetector::new(self.bytecode.clone());
        let _cross_chain_finality_findings = cross_chain_finality_detector.detect();
        modules_run += 1;

        let cross_chain_message_forge_detector = CrossChainMessageForgeDetector::new(self.bytecode.clone());
        let _cross_chain_message_forge_findings = cross_chain_message_forge_detector.detect();
        modules_run += 1;

        let bridge_signature_threshold_detector = BridgeSignatureThresholdDetector::new(self.bytecode.clone());
        let _bridge_signature_threshold_findings = bridge_signature_threshold_detector.detect();
        modules_run += 1;

        let lvr_extraction_detector = LvrExtractionDetector::new(self.bytecode.clone());
        let _lvr_extraction_findings = lvr_extraction_detector.detect();
        modules_run += 1;

        // Note: SandwichAttackDetector already used above from sandwich_attacks module

        let liquidity_removal_frontrun_detector = LiquidityRemovalFrontrunDetector::new(self.bytecode.clone());
        let _liquidity_removal_frontrun_findings = liquidity_removal_frontrun_detector.detect();
        modules_run += 1;

        let oracle_manipulation_frontrun_detector = OracleManipulationFrontrunDetector::new(self.bytecode.clone());
        let _oracle_manipulation_frontrun_findings = oracle_manipulation_frontrun_detector.detect();
        modules_run += 1;

        let flash_loan_price_manipulation_detector = FlashLoanPriceManipulationDetector::new(self.bytecode.clone());
        let _flash_loan_price_manipulation_findings = flash_loan_price_manipulation_detector.detect();
        modules_run += 1;

        let interest_rate_manipulation_detector = InterestRateManipulationDetector::new(self.bytecode.clone());
        let _interest_rate_manipulation_findings = interest_rate_manipulation_detector.detect();
        modules_run += 1;

        let cyclic_arbitrage_detector = CyclicArbitrageDetector::new(self.bytecode.clone());
        let _cyclic_arbitrage_findings = cyclic_arbitrage_detector.detect();
        modules_run += 1;

        let priority_gas_auction_detector = PriorityGasAuctionDetector::new(self.bytecode.clone());
        let _priority_gas_auction_findings = priority_gas_auction_detector.detect();
        modules_run += 1;

        let toxic_flow_detector = ToxicFlowDetector::new(self.bytecode.clone());
        let _toxic_flow_findings = toxic_flow_detector.detect();
        modules_run += 1;

        let userop_replay_detector = UserOpReplayDetector::new(self.bytecode.clone());
        let _userop_replay_findings = userop_replay_detector.detect();
        modules_run += 1;

        let module_reentrancy_detector = ModuleReentrancyDetector::new(self.bytecode.clone());
        let _module_reentrancy_findings = module_reentrancy_detector.detect();
        modules_run += 1;

        let vault_fee_manipulation_detector = VaultFeeManipulationDetector::new(self.bytecode.clone());
        let _vault_fee_manipulation_findings = vault_fee_manipulation_detector.detect();
        modules_run += 1;

        let withdrawal_queue_dos_detector = WithdrawalQueueDosDetector::new(self.bytecode.clone());
        let _withdrawal_queue_dos_findings = withdrawal_queue_dos_detector.detect();
        modules_run += 1;

        let vault_migration_attack_detector = VaultMigrationAttackDetector::new(self.bytecode.clone());
        let _vault_migration_attack_findings = vault_migration_attack_detector.detect();
        modules_run += 1;

        let yield_stripping_detector = YieldStrippingDetector::new(self.bytecode.clone());
        let _yield_stripping_findings = yield_stripping_detector.detect();
        modules_run += 1;

        let perp_funding_griefing_detector = PerpFundingGriefingDetector::new(self.bytecode.clone());
        let _perp_funding_griefing_findings = perp_funding_griefing_detector.detect();
        modules_run += 1;

        let insurance_fund_drain_detector = InsuranceFundDrainDetector::new(self.bytecode.clone());
        let _insurance_fund_drain_findings = insurance_fund_drain_detector.detect();
        modules_run += 1;

        let nft_fractionalization_attack_detector = NftFractionalizationAttackDetector::new(self.bytecode.clone());
        let _nft_fractionalization_attack_findings = nft_fractionalization_attack_detector.detect();
        modules_run += 1;

        let nft_wash_trading_detector = NftWashTradingDetector::new(self.bytecode.clone());
        let _nft_wash_trading_findings = nft_wash_trading_detector.detect();
        modules_run += 1;

        let erc721_reentrancy_callback_detector = Erc721ReentrancyCallbackDetector::new(self.bytecode.clone());
        let _erc721_reentrancy_callback_findings = erc721_reentrancy_callback_detector.detect();
        modules_run += 1;

        let rental_nft_theft_detector = RentalNftTheftDetector::new(self.bytecode.clone());
        let _rental_nft_theft_findings = rental_nft_theft_detector.detect();
        modules_run += 1;

        let token_bound_account_drain_detector = TokenBoundAccountDrainDetector::new(self.bytecode.clone());
        let _token_bound_account_drain_findings = token_bound_account_drain_detector.detect();
        modules_run += 1;

        let erc6551_reentrancy_detector = Erc6551ReentrancyDetector::new(self.bytecode.clone());
        let _erc6551_reentrancy_findings = erc6551_reentrancy_detector.detect();
        modules_run += 1;

        let dynamic_nft_manipulation_detector = DynamicNftManipulationDetector::new(self.bytecode.clone());
        let _dynamic_nft_manipulation_findings = dynamic_nft_manipulation_detector.detect();
        modules_run += 1;

        let eip5656_mcopy_bug_detector = Eip5656McopyBugDetector::new(self.bytecode.clone());
        let _eip5656_mcopy_bug_findings = eip5656_mcopy_bug_detector.detect();
        modules_run += 1;

        let eip6780_selfdestruct_change_detector = Eip6780SelfdestructChangeDetector::new(self.bytecode.clone());
        let _eip6780_selfdestruct_change_findings = eip6780_selfdestruct_change_detector.detect();
        modules_run += 1;

        let push0_opcode_bug_detector = Push0OpcodeBugDetector::new(self.bytecode.clone());
        let _push0_opcode_bug_findings = push0_opcode_bug_detector.detect();
        modules_run += 1;

        let eof_container_manipulation_detector = EofContainerManipulationDetector::new(self.bytecode.clone());
        let _eof_container_manipulation_findings = eof_container_manipulation_detector.detect();
        modules_run += 1;

        let vote_delegation_attack_detector = VoteDelegationAttackDetector::new(self.bytecode.clone());
        let _vote_delegation_attack_findings = vote_delegation_attack_detector.detect();
        modules_run += 1;

        let liquid_democracy_attack_detector = LiquidDemocracyAttackDetector::new(self.bytecode.clone());
        let _liquid_democracy_attack_findings = liquid_democracy_attack_detector.detect();
        modules_run += 1;

        let rage_quit_attack_detector = RageQuitAttackDetector::new(self.bytecode.clone());
        let _rage_quit_attack_findings = rage_quit_attack_detector.detect();
        modules_run += 1;

        let zk_soundness_break_detector = ZkSoundnessBreakDetector::new(self.bytecode.clone());
        let _zk_soundness_break_findings = zk_soundness_break_detector.detect();
        modules_run += 1;

        let polynomial_commitment_attack_detector = PolynomialCommitmentAttackDetector::new(self.bytecode.clone());
        let _polynomial_commitment_attack_findings = polynomial_commitment_attack_detector.detect();
        modules_run += 1;

        let fiat_shamir_weakness_detector = FiatShamirWeaknessDetector::new(self.bytecode.clone());
        let _fiat_shamir_weakness_findings = fiat_shamir_weakness_detector.detect();
        modules_run += 1;

        let pairing_check_bypass_detector = PairingCheckBypassDetector::new(self.bytecode.clone());
        let _pairing_check_bypass_findings = pairing_check_bypass_detector.detect();
        modules_run += 1;

        let creator_token_royalty_bypass_detector = CreatorTokenRoyaltyBypassDetector::new(self.bytecode.clone());
        let _creator_token_royalty_bypass_findings = creator_token_royalty_bypass_detector.detect();
        modules_run += 1;

        let mev_blocker_bypass_detector = MevBlockerBypassDetector::new(self.bytecode.clone());
        let _mev_blocker_bypass_findings = mev_blocker_bypass_detector.detect();
        modules_run += 1;

        let private_mempool_leak_detector = PrivateMempoolLeakDetector::new(self.bytecode.clone());
        let _private_mempool_leak_findings = private_mempool_leak_detector.detect();
        modules_run += 1;

        let shielded_pool_linkability_detector = ShieldedPoolLinkabilityDetector::new(self.bytecode.clone());
        let _shielded_pool_linkability_findings = shielded_pool_linkability_detector.detect();
        modules_run += 1;

        let gas_price_manipulation_detector = GasPriceManipulationDetector::new(self.bytecode.clone());
        let _gas_price_manipulation_findings = gas_price_manipulation_detector.detect();
        modules_run += 1;

        let challenge_period_griefing_detector = ChallengePeriodGriefingDetector::new(self.bytecode.clone());
        let _challenge_period_griefing_findings = challenge_period_griefing_detector.detect();
        modules_run += 1;

        let data_withholding_attack_detector = DataWithholdingAttackDetector::new(self.bytecode.clone());
        let _data_withholding_attack_findings = data_withholding_attack_detector.detect();
        modules_run += 1;

        let withdrawal_censorship_detector = WithdrawalCensorshipDetector::new(self.bytecode.clone());
        let _withdrawal_censorship_findings = withdrawal_censorship_detector.detect();
        modules_run += 1;

        let forced_exit_griefing_detector = ForcedExitGriefingDetector::new(self.bytecode.clone());
        let _forced_exit_griefing_findings = forced_exit_griefing_detector.detect();
        modules_run += 1;

        let tokenized_security_compliance_bypass_detector = TokenizedSecurityComplianceBypassDetector::new(self.bytecode.clone());
        let _tokenized_security_compliance_bypass_findings = tokenized_security_compliance_bypass_detector.detect();
        modules_run += 1;

        let kyc_whitelist_bypass_detector = KycWhitelistBypassDetector::new(self.bytecode.clone());
        let _kyc_whitelist_bypass_findings = kyc_whitelist_bypass_detector.detect();
        modules_run += 1;

        let transfer_restriction_circumvention_detector = TransferRestrictionCircumventionDetector::new(self.bytecode.clone());
        let _transfer_restriction_circumvention_findings = transfer_restriction_circumvention_detector.detect();
        modules_run += 1;

        let oracle_staleness_abuse_detector = OracleStalenessAbuseDetector::new(self.bytecode.clone());
        let _oracle_staleness_abuse_findings = oracle_staleness_abuse_detector.detect();
        modules_run += 1;

        let oracle_round_id_manipulation_detector = OracleRoundIdManipulationDetector::new(self.bytecode.clone());
        let _oracle_round_id_manipulation_findings = oracle_round_id_manipulation_detector.detect();
        modules_run += 1;

        // === 72 NEW DETECTORS ===
        let accredited_investor_verification_findings = AccreditedInvestorVerificationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let accumulator_decumulator_findings = AccumulatorDecumulatorDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let amm_k_value_manipulation_findings = AmmKValueManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let autocallable_barrier_manipulation_findings = AutocallableBarrierManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let aztec_nullifier_collision_findings = AztecNullifierCollisionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let biometric_hash_collision_findings = BiometricHashCollisionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let bridge_rebalancing_exploitation_findings = BridgeRebalancingExploitationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let commitment_scheme_malleability_findings = CommitmentSchemeMalleabilityDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let conditional_token_split_exploit_findings = ConditionalTokenSplitExploitDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let consensus_layer_withdrawal_delay_findings = ConsensusLayerWithdrawalDelayDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let credential_revocation_bypass_findings = CredentialRevocationBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let credit_default_swap_settlement_findings = CreditDefaultSwapSettlementDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let cross_chain_arbitrage_frontrun_findings = CrossChainArbitrageFrontrunDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let cross_domain_sandwich_findings = CrossDomainSandwichDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dao_proposal_spamming_findings = DaoProposalSpammingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dao_vote_buying_findings = DaoVoteBuyingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dex_router_slippage_manipulation_findings = DexRouterSlippageManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let did_registry_hijack_findings = DidRegistryHijackDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let did_resolver_manipulation_findings = DidResolverManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dividend_distribution_manipulation_findings = DividendDistributionManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dual_currency_product_findings = DualCurrencyProductDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let dynamic_nft_state_manipulation_findings = DynamicNftStateManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let endorsement_bribery_findings = EndorsementBriberyDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let game_economy_inflation_findings = GameEconomyInflationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let ido_bot_frontrun_findings = IdoBotFrontrunDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let insurance_pool_solvency_findings = InsurancePoolSolvencyDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let interchain_liquidation_race_findings = InterchainLiquidationRaceDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let interest_rate_swap_curve_manipulation_findings = InterestRateSwapCurveManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let kyc_aml_bypass_findings = KycAmlBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let liquid_staking_depeg_findings = LiquidStakingDepegDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let liquidity_provision_gaming_findings = LiquidityProvisionGamingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let market_maker_collusion_findings = MarketMakerCollusionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let multi_chain_oracle_latency_exploit_findings = MultiChainOracleLatencyExploitDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let nft_game_item_duplication_findings = NftGameItemDuplicationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let nft_rarity_manipulation_findings = NftRarityManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let nullifier_double_spend_findings = NullifierDoubleSpendDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let options_expiry_pinning_findings = OptionsExpiryPinningDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let orderbook_spoofing_findings = OrderbookSpoofingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let outcome_manipulation_before_resolution_findings = OutcomeManipulationBeforeResolutionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let parametric_insurance_trigger_manipulation_findings = ParametricInsuranceTriggerManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let perpetual_futures_funding_rate_manipulation_findings = PerpetualFuturesFundingRateManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let play_to_earn_reward_manipulation_findings = PlayToEarnRewardManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let prediction_market_oracle_front_running_findings = PredictionMarketOracleFrontRunningDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let principal_protected_note_findings = PrincipalProtectedNoteDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let refund_mechanism_exploit_findings = RefundMechanismExploitDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let regulatory_reporting_evasion_findings = RegulatoryReportingEvasionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let reputation_score_manipulation_findings = ReputationScoreManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let restaking_reward_calculation_exploit_findings = RestakingRewardCalculationExploitDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let slashing_condition_manipulation_findings = SlashingConditionManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let stealth_address_linkability_findings = StealthAddressLinkabilityDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let stealth_address_linkage_findings = StealthAddressLinkageDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let subscription_griefing_findings = SubscriptionGriefingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let subscription_payment_manipulation_findings = SubscriptionPaymentManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let swaption_volatility_manipulation_findings = SwaptionVolatilityManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let sybil_attack_prevention_bypass_findings = SybilAttackPreventionBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let sybil_resistance_bypass_findings = SybilResistanceBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let synthetic_asset_collateral_findings = SyntheticAssetCollateralDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let token_unlock_schedule_bypass_findings = TokenUnlockScheduleBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let tornado_cash_anonymity_set_reduction_findings = TornadoCashAnonymitySetReductionDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let total_return_swap_collateral_findings = TotalReturnSwapCollateralDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let tournament_prize_manipulation_findings = TournamentPrizeManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let transfer_restriction_bypass_findings = TransferRestrictionBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let trust_graph_poisoning_findings = TrustGraphPoisoningDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let validator_exit_griefing_findings = ValidatorExitGriefingDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let variance_swap_vega_exposure_findings = VarianceSwapVegaExposureDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let verifiable_credential_replay_findings = VerifiableCredentialReplayDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let verifiable_presentation_forgery_findings = VerifiablePresentationForgeryDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let vesting_cliff_manipulation_findings = VestingCliffManipulationDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let virtual_land_ownership_dispute_findings = VirtualLandOwnershipDisputeDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let whitelist_bypass_findings = WhitelistBypassDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let yield_enhancement_product_findings = YieldEnhancementProductDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;
        let zkp_circuit_soundness_exploit_findings = ZkpCircuitSoundnessExploitDetector::new(self.bytecode.clone()).detect();
        modules_run += 1;

        let analysis_duration = start_time.elapsed().as_millis() as u64;
        
        // Calculate comprehensive metrics
        let coverage_metrics = self.calculate_coverage_metrics(analysis_duration, modules_run);
        
        let mut total_vulnerabilities = reentrancy_vulnerabilities.len() as u32 +
                                         integer_vulnerabilities.len() as u32 +
                                         economic_vulnerabilities.len() as u32 +
                                         upgrade_vulnerabilities.len() as u32 +
                                         sandwich_vulnerabilities.len() as u32 +
                                         time_vulnerabilities.len() as u32 +
                                         cross_contract_vulnerabilities.len() as u32 +
                                         bridge_vulnerabilities.len() as u32 +
                                         protocol_dependency_vulnerabilities.len() as u32 +
                                         defi_primitive_vulnerabilities.len() as u32 +
                                         state_manipulation_vulnerabilities.len() as u32 +
                                         mev_attack_vulnerabilities.len() as u32 +
                                         atomic_composability_vulnerabilities.len() as u32 +
                                         protocol_integration_vulnerabilities.len() as u32 +
                                         advanced_mev_vulnerabilities.len() as u32 +
                                         gas_economic_vulnerabilities.len() as u32 +
                                         flash_loan_vulnerabilities.len() as u32 +
                                         data_integrity_vulnerabilities.len() as u32 +
                                         // NEW analyzers
                                         layer2_vulnerabilities.len() as u32 +
                                         account_abstraction_vulnerabilities.len() as u32 +
                                         intent_protocol_vulnerabilities.len() as u32 +
                                         hooks_callback_vulnerabilities.len() as u32 +
                                         concentrated_liquidity_vulnerabilities.len() as u32 +
                                         privacy_zk_vulnerabilities.len() as u32 +
                                         slippage_vulnerabilities.len() as u32 +
                                         defi_composability_risks.len() as u32 +
                                         race_condition_vulnerabilities.len() as u32 +
                                         arbitrage_vulnerabilities.len() as u32 +
                                         proxy_vulnerabilities.len() as u32 +
                                         composability_attacks.len() as u32 +
                                         oracle_manipulation_vulnerabilities.len() as u32 +
                                         access_control_vulnerabilities.len() as u32 +
                                         mev_protection_vulnerabilities.len() as u32 +
                                         censorship_vulnerabilities.len() as u32 +
                                         invariant_violations.len() as u32 +
                                         precision_vulnerabilities.len() as u32 +
                                         signature_replay_vulnerabilities.len() as u32;

        let overall_confidence = if modules_run > 0 {
            total_confidence / modules_run as f32
        } else {
            0.0
        };

        // Run advanced security modules
        let governance_vulnerabilities = if self.enable_governance_analysis {
            let mut governance_detector = GovernanceAttackDetector::new(self.bytecode.clone());
            let govs = governance_detector.detect_governance_attacks();
            total_vulnerabilities += govs.len() as u32;
            total_confidence += self.calculate_governance_confidence(&govs);
            modules_run += 1;
            govs
        } else {
            Vec::new()
        };

        let oracle_infrastructure_vulnerabilities = if self.enable_oracle_infrastructure_analysis {
            let mut oracle_analyzer = OracleInfrastructureAnalyzer::new(self.bytecode.clone());
            let oracles = oracle_analyzer.analyze_oracle_infrastructure();
            total_vulnerabilities += oracles.len() as u32;
            total_confidence += self.calculate_oracle_infrastructure_confidence(&oracles);
            modules_run += 1;
            oracles
        } else {
            Vec::new()
        };

        let lp_economic_vulnerabilities = if self.enable_lp_economic_analysis {
            let lp_analyzer = LPEconomicAttackAnalyzer::new(self.bytecode.clone());
            let lps = lp_analyzer.analyze_lp_economic_attacks();
            total_vulnerabilities += lps.len() as u32;
            total_confidence += self.calculate_lp_economic_confidence(&lps);
            modules_run += 1;
            lps
        } else {
            Vec::new()
        };

        let black_swan_vulnerabilities = if self.enable_black_swan_analysis {
            let black_swan_simulator = BlackSwanSimulator::new(self.bytecode.clone());
            let swans = black_swan_simulator.simulate_black_swan_events();
            total_vulnerabilities += swans.len() as u32;
            total_confidence += self.calculate_black_swan_confidence(&swans);
            modules_run += 1;
            swans
        } else {
            Vec::new()
        };

        let multi_vector_vulnerabilities = if self.enable_multi_vector_analysis {
            let mut multi_vector_simulator = MultiVectorAttackSimulator::new(self.bytecode.clone(), 1000000.0);
            let multis = multi_vector_simulator.simulate_coordinated_attacks();
            total_vulnerabilities += multis.len() as u32;
            total_confidence += self.calculate_multi_vector_confidence(&multis);
            modules_run += 1;
            multis
        } else {
            Vec::new()
        };

        let ai_detected_vulnerabilities = if self.enable_ai_adaptive_analysis {
            let mut ai_detector = AIAdaptiveAttackDetector::new(self.bytecode.clone());
            let ais = ai_detector.detect_ai_powered_attacks();
            total_vulnerabilities += ais.len() as u32;
            total_confidence += self.calculate_ai_detected_confidence(&ais);
            modules_run += 1;
            ais
        } else {
            Vec::new()
        };

        let infrastructure_vulnerabilities = if self.enable_infrastructure_analysis {
            let infra_analyzer = InfrastructureRiskAnalyzer::new(self.bytecode.clone());
            let infras = infra_analyzer.analyze_infrastructure_risks();
            total_vulnerabilities += infras.len() as u32;
            total_confidence += self.calculate_infrastructure_confidence(&infras);
            modules_run += 1;
            infras
        } else {
            Vec::new()
        };

        // Final coverage analyzers (always run - critical vulnerabilities)
        let short_address_detector = ShortAddressDetector::new(self.bytecode.clone());
        let mut short_address_vulnerabilities = short_address_detector.detect_vulnerabilities();
        total_vulnerabilities += short_address_vulnerabilities.len() as u32;
        modules_run += 1;

        let create2_detector = CREATE2ExploitDetector::new(self.bytecode.clone());
        let mut create2_vulnerabilities = create2_detector.detect_vulnerabilities();
        total_vulnerabilities += create2_vulnerabilities.len() as u32;
        modules_run += 1;

        let selfdestruct_analyzer = SelfdestructAnalyzer::new(self.bytecode.clone());
        let mut selfdestruct_vulnerabilities = selfdestruct_analyzer.analyze();
        total_vulnerabilities += selfdestruct_vulnerabilities.len() as u32;
        modules_run += 1;

        let weird_erc20_detector = WeirdERC20Detector::new(self.bytecode.clone());
        let mut weird_erc20_vulnerabilities = weird_erc20_detector.detect_vulnerabilities();
        total_vulnerabilities += weird_erc20_vulnerabilities.len() as u32;
        modules_run += 1;

        let readonly_reentrancy_detector = ReadOnlyReentrancyDetector::new(self.bytecode.clone());
        let mut readonly_reentrancy_vulnerabilities = readonly_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += readonly_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let basefee_manipulation_detector = BaseFeeManipulationDetector::new(self.bytecode.clone());
        let mut balance_manipulation_vulnerabilities = basefee_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += balance_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let nft_detector = NFTVulnerabilityDetector::new(self.bytecode.clone());
        let mut nft_vulnerabilities = nft_detector.detect_vulnerabilities();
        total_vulnerabilities += nft_vulnerabilities.len() as u32;
        modules_run += 1;

        let compiler_bug_detector = CompilerBugDetector::new(self.bytecode.clone());
        let mut compiler_bug_vulnerabilities = compiler_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += compiler_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let signature_detector = SignatureVulnDetector::new(self.bytecode.clone());
        let signature_vulnerabilities = signature_detector.detect_vulnerabilities();
        total_vulnerabilities += signature_vulnerabilities.len() as u32;
        modules_run += 1;

        let return_bomb_detector = ReturnBombDetector::new(self.bytecode.clone());
        let return_bomb_vulnerabilities = return_bomb_detector.detect_vulnerabilities();
        total_vulnerabilities += return_bomb_vulnerabilities.len() as u32;
        modules_run += 1;

        let extcodesize_bypass_detector = ExtcodesizeBypassDetector::new(self.bytecode.clone());
        let extcodesize_bypass_vulnerabilities = extcodesize_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += extcodesize_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let dirty_bits_detector = DirtyBitsDetector::new(self.bytecode.clone());
        let dirty_bits_vulnerabilities = dirty_bits_detector.detect_vulnerabilities();
        total_vulnerabilities += dirty_bits_vulnerabilities.len() as u32;
        modules_run += 1;

        let transient_storage_detector = TransientStorageDetector::new(self.bytecode.clone());
        let transient_storage_vulnerabilities = transient_storage_detector.detect_vulnerabilities();
        total_vulnerabilities += transient_storage_vulnerabilities.len() as u32;
        modules_run += 1;

        let multicall_failure_detector = MulticallFailureDetector::new(self.bytecode.clone());
        let multicall_failure_vulnerabilities = multicall_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += multicall_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let callback_gas_detector = CallbackGasDetector::new(self.bytecode.clone());
        let callback_gas_vulnerabilities = callback_gas_detector.detect_vulnerabilities();
        total_vulnerabilities += callback_gas_vulnerabilities.len() as u32;
        modules_run += 1;

        let basefee_detector = BaseFeeManipulationDetector::new(self.bytecode.clone());
        let basefee_vulnerabilities = basefee_detector.detect_vulnerabilities();
        total_vulnerabilities += basefee_vulnerabilities.len() as u32;
        modules_run += 1;

        let time_manipulation_detector = TimeManipulationDetector::new(self.bytecode.clone());
        let time_manipulation_vulnerabilities = time_manipulation_detector.analyze();
        total_vulnerabilities += time_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let gas_griefing_detector = GasGriefingDetector::new(self.bytecode.clone());
        let gas_griefing_vulnerabilities = gas_griefing_detector.analyze();
        total_vulnerabilities += gas_griefing_vulnerabilities.len() as u32;
        modules_run += 1;

        let aa_bundler_detector = AABundlerDetector::new(self.bytecode.clone());
        let aa_bundler_vulnerabilities = aa_bundler_detector.detect_vulnerabilities();
        total_vulnerabilities += aa_bundler_vulnerabilities.len() as u32;
        modules_run += 1;

        let aa_nonce_management_detector = AaNonceManagementDetector::new(self.bytecode.clone());
        let aa_nonce_management_vulnerabilities = aa_nonce_management_detector.detect_vulnerabilities();
        total_vulnerabilities += aa_nonce_management_vulnerabilities.len() as u32;
        modules_run += 1;

        let aave_governance_short_timelock_detector = AaveGovernanceShortTimelockDetector::new(self.bytecode.clone());
        let aave_governance_short_timelock_vulnerabilities = aave_governance_short_timelock_detector.detect_vulnerabilities();
        total_vulnerabilities += aave_governance_short_timelock_vulnerabilities.len() as u32;
        modules_run += 1;

        let aave_liquidation_manipulation_detector = AaveLiquidationManipulationDetector::new(self.bytecode.clone());
        let aave_liquidation_manipulation_vulnerabilities = aave_liquidation_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += aave_liquidation_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let aave_v3_emode_liquidation_detector = AaveV3EmodeLiquidationDetector::new(self.bytecode.clone());
        let aave_v3_emode_liquidation_vulnerabilities = aave_v3_emode_liquidation_detector.detect_vulnerabilities();
        total_vulnerabilities += aave_v3_emode_liquidation_vulnerabilities.len() as u32;
        modules_run += 1;

        let aave_v3_isolation_mode_detector = AaveV3IsolationModeDetector::new(self.bytecode.clone());
        let aave_v3_isolation_mode_vulnerabilities = aave_v3_isolation_mode_detector.detect_vulnerabilities();
        total_vulnerabilities += aave_v3_isolation_mode_vulnerabilities.len() as u32;
        modules_run += 1;

        let abi_encoding_edge_case_detector = ABIEncodingEdgeCaseDetector::new(self.bytecode.clone());
        let abi_encoding_edge_case_vulnerabilities = abi_encoding_edge_case_detector.detect_vulnerabilities();
        total_vulnerabilities += abi_encoding_edge_case_vulnerabilities.len() as u32;
        modules_run += 1;

        let account_bound_token_detector = AccountBoundTokenDetector::new(self.bytecode.clone());
        let account_bound_token_vulnerabilities = account_bound_token_detector.detect_vulnerabilities();
        total_vulnerabilities += account_bound_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let across_protocol_spoke_pool_relay_detector = AcrossProtocolDetector::new(self.bytecode.clone());
        let across_protocol_spoke_pool_relay_vulnerabilities = across_protocol_spoke_pool_relay_detector.detect_vulnerabilities();
        total_vulnerabilities += across_protocol_spoke_pool_relay_vulnerabilities.len() as u32;
        modules_run += 1;

        let advanced_reentrancy_detector = AdvancedReentrancyDetector::new(self.bytecode.clone());
        let advanced_reentrancy_vulnerabilities = advanced_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += advanced_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let adversarial_input_ml_detector = AdversarialInputMLDetector::new(self.bytecode.clone());
        let adversarial_input_ml_vulnerabilities = adversarial_input_ml_detector.detect_vulnerabilities();
        total_vulnerabilities += adversarial_input_ml_vulnerabilities.len() as u32;
        modules_run += 1;

        let ai_agent_mev_detector = AiAgentMevDetector::new(self.bytecode.clone());
        let ai_agent_mev_vulnerabilities = ai_agent_mev_detector.detect_vulnerabilities();
        total_vulnerabilities += ai_agent_mev_vulnerabilities.len() as u32;
        modules_run += 1;

        let airdrop_claim_frontrunning_detector = AirdropClaimFrontrunningDetector::new(self.bytecode.clone());
        let airdrop_claim_frontrunning_vulnerabilities = airdrop_claim_frontrunning_detector.detect_vulnerabilities();
        total_vulnerabilities += airdrop_claim_frontrunning_vulnerabilities.len() as u32;
        modules_run += 1;

        let airdrop_farming_detector = AirdropFarmingDetector::new(self.bytecode.clone());
        let airdrop_farming_vulnerabilities = airdrop_farming_detector.detect_vulnerabilities();
        total_vulnerabilities += airdrop_farming_vulnerabilities.len() as u32;
        modules_run += 1;

        let alchemy_modular_account_detector = AlchemyModularAccountDetector::new(self.bytecode.clone());
        let alchemy_modular_account_vulnerabilities = alchemy_modular_account_detector.detect_vulnerabilities();
        total_vulnerabilities += alchemy_modular_account_vulnerabilities.len() as u32;
        modules_run += 1;

        let algorithmic_stablecoin_detector = AlgorithmicStablecoinDetector::new(self.bytecode.clone());
        let algorithmic_stablecoin_vulnerabilities = algorithmic_stablecoin_detector.detect_vulnerabilities();
        total_vulnerabilities += algorithmic_stablecoin_vulnerabilities.len() as u32;
        modules_run += 1;

        let AMM_imbalance_attack_detector = AMMImbalanceAttackDetector::new(self.bytecode.clone());
        let AMM_imbalance_attack_vulnerabilities = AMM_imbalance_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += AMM_imbalance_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let AMM_k_invariant_detector = AmmKInvariantDetector::new(self.bytecode.clone());
        let AMM_k_invariant_vulnerabilities = AMM_k_invariant_detector.detect_vulnerabilities();
        total_vulnerabilities += AMM_k_invariant_vulnerabilities.len() as u32;
        modules_run += 1;

        let AMM_pool_management_detector = AmmPoolManagementDetector::new(self.bytecode.clone());
        let AMM_pool_management_vulnerabilities = AMM_pool_management_detector.detect_vulnerabilities();
        total_vulnerabilities += AMM_pool_management_vulnerabilities.len() as u32;
        modules_run += 1;

        let amm_spot_price_detector = AMMSpotPriceDetector::new(self.bytecode.clone());
        let amm_spot_price_vulnerabilities = amm_spot_price_detector.detect_vulnerabilities();
        total_vulnerabilities += amm_spot_price_vulnerabilities.len() as u32;
        modules_run += 1;

        let amortization_schedule_exploit_detector = AmortizationScheduleExploitDetector::new(self.bytecode.clone());
        let amortization_schedule_exploit_vulnerabilities = amortization_schedule_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += amortization_schedule_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let angle_protocol_oracle_desync_detector = AngleProtocolOracleDesyncDetector::new(self.bytecode.clone());
        let angle_protocol_oracle_desync_vulnerabilities = angle_protocol_oracle_desync_detector.detect_vulnerabilities();
        total_vulnerabilities += angle_protocol_oracle_desync_vulnerabilities.len() as u32;
        modules_run += 1;

        let anomaly_based_vulnerability_detector = AnomalyBasedVulnerabilityDetector::new(self.bytecode.clone());
        let anomaly_based_vulnerability_vulnerabilities = anomaly_based_vulnerability_detector.detect_vulnerabilities();
        total_vulnerabilities += anomaly_based_vulnerability_vulnerabilities.len() as u32;
        modules_run += 1;

        let api3_dapi_attack_detector = Api3DapiAttackDetector::new(self.bytecode.clone());
        let api3_dapi_attack_vulnerabilities = api3_dapi_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += api3_dapi_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let array_delete_bug_detector = ArrayDeleteBugDetector::new(self.bytecode.clone());
        let array_delete_bug_vulnerabilities = array_delete_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += array_delete_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let asian_option_price_path_gaming_detector = AsianOptionPricePathGamingDetector::new(self.bytecode.clone());
        let asian_option_price_path_gaming_vulnerabilities = asian_option_price_path_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += asian_option_price_path_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let assembly_unsafe_memory_detector = AssemblyUnsafeMemoryDetector::new(self.bytecode.clone());
        let assembly_unsafe_memory_vulnerabilities = assembly_unsafe_memory_detector.detect_vulnerabilities();
        total_vulnerabilities += assembly_unsafe_memory_vulnerabilities.len() as u32;
        modules_run += 1;

        let assert_require_misuse_detector = AssertRequireMisuseDetector::new(self.bytecode.clone());
        let assert_require_misuse_vulnerabilities = assert_require_misuse_detector.detect_vulnerabilities();
        total_vulnerabilities += assert_require_misuse_vulnerabilities.len() as u32;
        modules_run += 1;

        let astria_sequencer_ordering_detector = AstriaSequencerOrderingDetector::new(self.bytecode.clone());
        let astria_sequencer_ordering_vulnerabilities = astria_sequencer_ordering_detector.detect_vulnerabilities();
        total_vulnerabilities += astria_sequencer_ordering_vulnerabilities.len() as u32;
        modules_run += 1;

        let atomic_cross_chain_detector = AtomicCrossChainDetector::new(self.bytecode.clone());
        let atomic_cross_chain_vulnerabilities = atomic_cross_chain_detector.detect_vulnerabilities();
        total_vulnerabilities += atomic_cross_chain_vulnerabilities.len() as u32;
        modules_run += 1;

        let auction_mechanism_detector = AuctionMechanismDetector::new(self.bytecode.clone());
        let auction_mechanism_vulnerabilities = auction_mechanism_detector.detect_vulnerabilities();
        total_vulnerabilities += auction_mechanism_vulnerabilities.len() as u32;
        modules_run += 1;

        let auto_compounding_vault_timing_detector = AutoCompoundingVaultTimingDetector::new(self.bytecode.clone());
        let auto_compounding_vault_timing_vulnerabilities = auto_compounding_vault_timing_detector.detect_vulnerabilities();
        total_vulnerabilities += auto_compounding_vault_timing_vulnerabilities.len() as u32;
        modules_run += 1;

        let autocallable_note_barrier_gaming_detector = AutocallableNoteBarrierGamingDetector::new(self.bytecode.clone());
        let autocallable_note_barrier_gaming_vulnerabilities = autocallable_note_barrier_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += autocallable_note_barrier_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let automated_market_maker_detector = AutomatedMarketMakerDetector::new(self.bytecode.clone());
        let automated_market_maker_vulnerabilities = automated_market_maker_detector.detect_vulnerabilities();
        total_vulnerabilities += automated_market_maker_vulnerabilities.len() as u32;
        modules_run += 1;

        let axelar_threshold_signature_detector = AxelarThresholdSignatureDetector::new(self.bytecode.clone());
        let axelar_threshold_signature_vulnerabilities = axelar_threshold_signature_detector.detect_vulnerabilities();
        total_vulnerabilities += axelar_threshold_signature_vulnerabilities.len() as u32;
        modules_run += 1;

        let babylon_bitcoin_staking_detector = BabylonBitcoinStakingDetector::new(self.bytecode.clone());
        let babylon_bitcoin_staking_vulnerabilities = babylon_bitcoin_staking_detector.detect_vulnerabilities();
        total_vulnerabilities += babylon_bitcoin_staking_vulnerabilities.len() as u32;
        modules_run += 1;

        let back_running_state_read_detector = BackRunningStateReadDetector::new(self.bytecode.clone());
        let back_running_state_read_vulnerabilities = back_running_state_read_detector.detect_vulnerabilities();
        total_vulnerabilities += back_running_state_read_vulnerabilities.len() as u32;
        modules_run += 1;

        let bacon_protocol_cross_chain_forgery_detector = BaconProtocolCrossChainForgeryDetector::new(self.bytecode.clone());
        let bacon_protocol_cross_chain_forgery_vulnerabilities = bacon_protocol_cross_chain_forgery_detector.detect_vulnerabilities();
        total_vulnerabilities += bacon_protocol_cross_chain_forgery_vulnerabilities.len() as u32;
        modules_run += 1;

        let bad_debt_socialization_detector = BadDebtSocializationDetector::new(self.bytecode.clone());
        let bad_debt_socialization_vulnerabilities = bad_debt_socialization_detector.detect_vulnerabilities();
        total_vulnerabilities += bad_debt_socialization_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_readonly_reentrancy_enhanced_detector = BalancerReadOnlyReentrancyEnhancedDetector::new(self.bytecode.clone());
        let balancer_readonly_reentrancy_enhanced_vulnerabilities = balancer_readonly_reentrancy_enhanced_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_readonly_reentrancy_enhanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_v3_pool_creation_detector = BalancerV3PoolCreationDetector::new(self.bytecode.clone());
        let balancer_v3_pool_creation_vulnerabilities = balancer_v3_pool_creation_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_v3_pool_creation_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_v3_pool_hooks_reentrancy_detector = BalancerV3HooksDetector::new(self.bytecode.clone());
        let balancer_v3_pool_hooks_reentrancy_vulnerabilities = balancer_v3_pool_hooks_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_v3_pool_hooks_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_v3_precision_detector = BalancerV3PrecisionDetector::new(self.bytecode.clone());
        let balancer_v3_precision_vulnerabilities = balancer_v3_precision_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_v3_precision_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_vault_reentrancy_detector = BalancerVaultReentrancyDetector::new(self.bytecode.clone());
        let balancer_vault_reentrancy_vulnerabilities = balancer_vault_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_vault_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_weight_detector = BalancerWeightDetector::new(self.bytecode.clone());
        let balancer_weight_vulnerabilities = balancer_weight_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_weight_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_weighted_math_detector = BalancerWeightedMathDetector::new(self.bytecode.clone());
        let balancer_weighted_math_vulnerabilities = balancer_weighted_math_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_weighted_math_vulnerabilities.len() as u32;
        modules_run += 1;

        let balancer_weighted_pool_rate_detector = BalancerWeightedPoolRateDetector::new(self.bytecode.clone());
        let balancer_weighted_pool_rate_vulnerabilities = balancer_weighted_pool_rate_detector.detect_vulnerabilities();
        total_vulnerabilities += balancer_weighted_pool_rate_vulnerabilities.len() as u32;
        modules_run += 1;

        let band_protocol_reporter_collusion_detector = BandProtocolReporterCollusionDetector::new(self.bytecode.clone());
        let band_protocol_reporter_collusion_vulnerabilities = band_protocol_reporter_collusion_detector.detect_vulnerabilities();
        total_vulnerabilities += band_protocol_reporter_collusion_vulnerabilities.len() as u32;
        modules_run += 1;

        let basic_reentrancy_detector = BasicReentrancyDetector::new(self.bytecode.clone());
        let basic_reentrancy_vulnerabilities = basic_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += basic_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let batch_reentrancy_detector = BatchReentrancyDetector::new(self.bytecode.clone());
        let batch_reentrancy_vulnerabilities = batch_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += batch_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let beacon_proxy_implementation_detector = BeaconProxyImplementationDetector::new(self.bytecode.clone());
        let beacon_proxy_implementation_vulnerabilities = beacon_proxy_implementation_detector.detect_vulnerabilities();
        total_vulnerabilities += beacon_proxy_implementation_vulnerabilities.len() as u32;
        modules_run += 1;

        let beacon_root_detector = BeaconRootDetector::new(self.bytecode.clone());
        let beacon_root_vulnerabilities = beacon_root_detector.detect_vulnerabilities();
        total_vulnerabilities += beacon_root_vulnerabilities.len() as u32;
        modules_run += 1;

        let beanstalk_flash_loan_governance_detector = BeanstalkFlashLoanGovernanceDetector::new(self.bytecode.clone());
        let beanstalk_flash_loan_governance_vulnerabilities = beanstalk_flash_loan_governance_detector.detect_vulnerabilities();
        total_vulnerabilities += beanstalk_flash_loan_governance_vulnerabilities.len() as u32;
        modules_run += 1;

        let biconomy_session_key_detector = BiconomySessionKeyDetector::new(self.bytecode.clone());
        let biconomy_session_key_vulnerabilities = biconomy_session_key_detector.detect_vulnerabilities();
        total_vulnerabilities += biconomy_session_key_vulnerabilities.len() as u32;
        modules_run += 1;

        let bignumber_arithmetic_overflow_detector = BigNumberArithmeticOverflowDetector::new(self.bytecode.clone());
        let bignumber_arithmetic_overflow_vulnerabilities = bignumber_arithmetic_overflow_detector.detect_vulnerabilities();
        total_vulnerabilities += bignumber_arithmetic_overflow_vulnerabilities.len() as u32;
        modules_run += 1;

        let binary_option_price_pinning_detector = BinaryOptionPricePinningDetector::new(self.bytecode.clone());
        let binary_option_price_pinning_vulnerabilities = binary_option_price_pinning_detector.detect_vulnerabilities();
        total_vulnerabilities += binary_option_price_pinning_vulnerabilities.len() as u32;
        modules_run += 1;

        let black_scholes_approximation_detector = BlackScholesApproximationDetector::new(self.bytecode.clone());
        let black_scholes_approximation_vulnerabilities = black_scholes_approximation_detector.detect_vulnerabilities();
        total_vulnerabilities += black_scholes_approximation_vulnerabilities.len() as u32;
        modules_run += 1;

        let blast_native_yield_detector = BlastNativeYieldDetector::new(self.bytecode.clone());
        let blast_native_yield_vulnerabilities = blast_native_yield_detector.detect_vulnerabilities();
        total_vulnerabilities += blast_native_yield_vulnerabilities.len() as u32;
        modules_run += 1;

        let blast_native_yield_rounding_detector = BlastNativeYieldRoundingDetector::new(self.bytecode.clone());
        let blast_native_yield_rounding_vulnerabilities = blast_native_yield_rounding_detector.detect_vulnerabilities();
        total_vulnerabilities += blast_native_yield_rounding_vulnerabilities.len() as u32;
        modules_run += 1;

        let blob_mev_extraction_detector = BlobMevExtractionDetector::new(self.bytecode.clone());
        let blob_mev_extraction_vulnerabilities = blob_mev_extraction_detector.detect_vulnerabilities();
        total_vulnerabilities += blob_mev_extraction_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_boundary_frontrunning_detector = BlockBoundaryFrontrunningDetector::new(self.bytecode.clone());
        let block_boundary_frontrunning_vulnerabilities = block_boundary_frontrunning_detector.detect_vulnerabilities();
        total_vulnerabilities += block_boundary_frontrunning_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_boundary_race_detector = BlockBoundaryRaceDetector::new(self.bytecode.clone());
        let block_boundary_race_vulnerabilities = block_boundary_race_detector.detect_vulnerabilities();
        total_vulnerabilities += block_boundary_race_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_builder_manipulation_detector = BlockBuilderManipulationDetector::new(self.bytecode.clone());
        let block_builder_manipulation_vulnerabilities = block_builder_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += block_builder_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_gas_limit_dos_detector = BlockGasLimitDosDetector::new(self.bytecode.clone());
        let block_gas_limit_dos_vulnerabilities = block_gas_limit_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += block_gas_limit_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_number_equality_detector = BlockNumberEqualityDetector::new(self.bytecode.clone());
        let block_number_equality_vulnerabilities = block_number_equality_detector.detect_vulnerabilities();
        total_vulnerabilities += block_number_equality_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_stuffing_detector = BlockStuffingDetector::new(self.bytecode.clone());
        let block_stuffing_vulnerabilities = block_stuffing_detector.detect_vulnerabilities();
        total_vulnerabilities += block_stuffing_vulnerabilities.len() as u32;
        modules_run += 1;

        let block_time_variance_gaming_detector = BlockTimeVarianceGamingDetector::new(self.bytecode.clone());
        let block_time_variance_gaming_vulnerabilities = block_time_variance_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += block_time_variance_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let blocklist_token_usdc_detector = BlocklistTokenUsdcDetector::new(self.bytecode.clone());
        let blocklist_token_usdc_vulnerabilities = blocklist_token_usdc_detector.detect_vulnerabilities();
        total_vulnerabilities += blocklist_token_usdc_vulnerabilities.len() as u32;
        modules_run += 1;

        let bls_aggregation_vulnerability_detector = BlsAggregationVulnerabilityDetector::new(self.bytecode.clone());
        let bls_aggregation_vulnerability_vulnerabilities = bls_aggregation_vulnerability_detector.detect_vulnerabilities();
        total_vulnerabilities += bls_aggregation_vulnerability_vulnerabilities.len() as u32;
        modules_run += 1;

        let blueberry_spell_vault_desync_detector = BlueberrySpellVaultDesyncDetector::new(self.bytecode.clone());
        let blueberry_spell_vault_desync_vulnerabilities = blueberry_spell_vault_desync_detector.detect_vulnerabilities();
        total_vulnerabilities += blueberry_spell_vault_desync_vulnerabilities.len() as u32;
        modules_run += 1;

        let bn254_pairing_dos_detector = Bn254PairingDosDetector::new(self.bytecode.clone());
        let bn254_pairing_dos_vulnerabilities = bn254_pairing_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += bn254_pairing_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let bundler_censorship_detector = BundlerCensorshipDetector::new(self.bytecode.clone());
        let bundler_censorship_vulnerabilities = bundler_censorship_detector.detect_vulnerabilities();
        total_vulnerabilities += bundler_censorship_vulnerabilities.len() as u32;
        modules_run += 1;

        let bundler_dos_detector = BundlerDosDetector::new(self.bytecode.clone());
        let bundler_dos_vulnerabilities = bundler_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += bundler_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let bytecode_verification_detector = BytecodeVerificationDetector::new(self.bytecode.clone());
        let bytecode_verification_vulnerabilities = bytecode_verification_detector.detect_vulnerabilities();
        total_vulnerabilities += bytecode_verification_vulnerabilities.len() as u32;
        modules_run += 1;

        let bytes_string_confusion_detector = BytesStringConfusionDetector::new(self.bytecode.clone());
        let bytes_string_confusion_vulnerabilities = bytes_string_confusion_detector.detect_vulnerabilities();
        total_vulnerabilities += bytes_string_confusion_vulnerabilities.len() as u32;
        modules_run += 1;

        let callback_reentrancy_detector = CallbackReentrancyDetector::new(self.bytecode.clone());
        let callback_reentrancy_vulnerabilities = callback_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += callback_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let calldata_compression_bug_detector = CalldataCompressionBugDetector::new(self.bytecode.clone());
        let calldata_compression_bug_vulnerabilities = calldata_compression_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += calldata_compression_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let calldata_expansion_dos_detector = CalldataExpansionDosDetector::new(self.bytecode.clone());
        let calldata_expansion_dos_vulnerabilities = calldata_expansion_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += calldata_expansion_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let calldata_tuple_bug_detector = CalldataTupleBugDetector::new(self.bytecode.clone());
        let calldata_tuple_bug_vulnerabilities = calldata_tuple_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += calldata_tuple_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let capability_based_escalation_detector = CapabilityBasedEscalationDetector::new(self.bytecode.clone());
        let capability_based_escalation_vulnerabilities = capability_based_escalation_detector.detect_vulnerabilities();
        total_vulnerabilities += capability_based_escalation_vulnerabilities.len() as u32;
        modules_run += 1;

        let caplet_floorlet_strike_gaming_detector = CapletFloorletStrikeGamingDetector::new(self.bytecode.clone());
        let caplet_floorlet_strike_gaming_vulnerabilities = caplet_floorlet_strike_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += caplet_floorlet_strike_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let celestia_blobstream_detector = CelestiaBlobstreamDetector::new(self.bytecode.clone());
        let celestia_blobstream_vulnerabilities = celestia_blobstream_detector.detect_vulnerabilities();
        total_vulnerabilities += celestia_blobstream_vulnerabilities.len() as u32;
        modules_run += 1;

        let cex_dex_arbitrage_timing_detector = CEXDEXArbitrageTimingDetector::new(self.bytecode.clone());
        let cex_dex_arbitrage_timing_vulnerabilities = cex_dex_arbitrage_timing_detector.detect_vulnerabilities();
        total_vulnerabilities += cex_dex_arbitrage_timing_vulnerabilities.len() as u32;
        modules_run += 1;

        let chain_opcode_difference_detector = ChainOpcodeDifferenceDetector::new(self.bytecode.clone());
        let chain_opcode_difference_vulnerabilities = chain_opcode_difference_detector.detect_vulnerabilities();
        total_vulnerabilities += chain_opcode_difference_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainid_hardcoding_detector = ChainIdHardcodingDetector::new(self.bytecode.clone());
        let chainid_hardcoding_vulnerabilities = chainid_hardcoding_detector.detect_vulnerabilities();
        total_vulnerabilities += chainid_hardcoding_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainlink_ccip_message_ordering_detector = ChainlinkCcipMessageOrderingDetector::new(self.bytecode.clone());
        let chainlink_ccip_message_ordering_vulnerabilities = chainlink_ccip_message_ordering_detector.detect_vulnerabilities();
        total_vulnerabilities += chainlink_ccip_message_ordering_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainlink_l2_sequencer_uptime_feed_detector = ChainlinkL2SequencerUptimeFeedDetector::new(self.bytecode.clone());
        let chainlink_l2_sequencer_uptime_feed_vulnerabilities = chainlink_l2_sequencer_uptime_feed_detector.detect_vulnerabilities();
        total_vulnerabilities += chainlink_l2_sequencer_uptime_feed_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainlink_ocr2_manipulation_detector = ChainlinkOCR2ManipulationDetector::new(self.bytecode.clone());
        let chainlink_ocr2_manipulation_vulnerabilities = chainlink_ocr2_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += chainlink_ocr2_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainlink_stale_price_detector = ChainlinkStalePriceDetector::new(self.bytecode.clone());
        let chainlink_stale_price_vulnerabilities = chainlink_stale_price_detector.detect_vulnerabilities();
        total_vulnerabilities += chainlink_stale_price_vulnerabilities.len() as u32;
        modules_run += 1;

        let chainlink_vrf_detector = ChainlinkVrfDetector::new(self.bytecode.clone());
        let chainlink_vrf_vulnerabilities = chainlink_vrf_detector.detect_vulnerabilities();
        total_vulnerabilities += chainlink_vrf_vulnerabilities.len() as u32;
        modules_run += 1;

        let channel_capacity_violation_detector = ChannelCapacityViolationDetector::new(self.bytecode.clone());
        let channel_capacity_violation_vulnerabilities = channel_capacity_violation_detector.detect_vulnerabilities();
        total_vulnerabilities += channel_capacity_violation_vulnerabilities.len() as u32;
        modules_run += 1;

        let chaos_butterfly_effect_detector = ChaosButterflyEffectDetector::new(self.bytecode.clone());
        let chaos_butterfly_effect_vulnerabilities = chaos_butterfly_effect_detector.detect_vulnerabilities();
        total_vulnerabilities += chaos_butterfly_effect_vulnerabilities.len() as u32;
        modules_run += 1;

        let checkpoint_vote_detector = CheckpointVoteDetector::new(self.bytecode.clone());
        let checkpoint_vote_vulnerabilities = checkpoint_vote_detector.detect_vulnerabilities();
        total_vulnerabilities += checkpoint_vote_vulnerabilities.len() as u32;
        modules_run += 1;

        let chooser_option_exercise_gaming_detector = ChooserOptionExerciseGamingDetector::new(self.bytecode.clone());
        let chooser_option_exercise_gaming_vulnerabilities = chooser_option_exercise_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += chooser_option_exercise_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let chronicle_validator_quorum_bypass_detector = ChronicleValidatorQuorumBypassDetector::new(self.bytecode.clone());
        let chronicle_validator_quorum_bypass_vulnerabilities = chronicle_validator_quorum_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += chronicle_validator_quorum_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let church_turing_violation_detector = ChurchTuringViolationDetector::new(self.bytecode.clone());
        let church_turing_violation_vulnerabilities = church_turing_violation_detector.detect_vulnerabilities();
        total_vulnerabilities += church_turing_violation_vulnerabilities.len() as u32;
        modules_run += 1;

        let collateral_isolation_detector = CollateralIsolationDetector::new(self.bytecode.clone());
        let collateral_isolation_vulnerabilities = collateral_isolation_detector.detect_vulnerabilities();
        total_vulnerabilities += collateral_isolation_vulnerabilities.len() as u32;
        modules_run += 1;

        let collateral_ratio_detector = CollateralRatioDetector::new(self.bytecode.clone());
        let collateral_ratio_vulnerabilities = collateral_ratio_detector.detect_vulnerabilities();
        total_vulnerabilities += collateral_ratio_vulnerabilities.len() as u32;
        modules_run += 1;

        let colony_reputation_mining_detector = ColonyReputationMiningDetector::new(self.bytecode.clone());
        let colony_reputation_mining_vulnerabilities = colony_reputation_mining_detector.detect_vulnerabilities();
        total_vulnerabilities += colony_reputation_mining_vulnerabilities.len() as u32;
        modules_run += 1;

        let commitment_scheme_weakness_detector = CommitmentSchemeWeaknessDetector::new(self.bytecode.clone());
        let commitment_scheme_weakness_vulnerabilities = commitment_scheme_weakness_detector.detect_vulnerabilities();
        total_vulnerabilities += commitment_scheme_weakness_vulnerabilities.len() as u32;
        modules_run += 1;

        let compact_signature_eip2098_detector = CompactSignatureEip2098Detector::new(self.bytecode.clone());
        let compact_signature_eip2098_vulnerabilities = compact_signature_eip2098_detector.detect_vulnerabilities();
        total_vulnerabilities += compact_signature_eip2098_vulnerabilities.len() as u32;
        modules_run += 1;

        let compliance_bypass_detector = ComplianceBypassDetector::new(self.bytecode.clone());
        let compliance_bypass_vulnerabilities = compliance_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += compliance_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let compliance_freeze_cascade_detector = ComplianceFreezeCascadeDetector::new(self.bytecode.clone());
        let compliance_freeze_cascade_vulnerabilities = compliance_freeze_cascade_detector.detect_vulnerabilities();
        total_vulnerabilities += compliance_freeze_cascade_vulnerabilities.len() as u32;
        modules_run += 1;

        let composability_invariant_violation_detector = ComposabilityInvariantViolationDetector::new(self.bytecode.clone());
        let composability_invariant_violation_vulnerabilities = composability_invariant_violation_detector.detect_vulnerabilities();
        total_vulnerabilities += composability_invariant_violation_vulnerabilities.len() as u32;
        modules_run += 1;

        let composable_stablecoin_detector = ComposableStablecoinDetector::new(self.bytecode.clone());
        let composable_stablecoin_vulnerabilities = composable_stablecoin_detector.detect_vulnerabilities();
        total_vulnerabilities += composable_stablecoin_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_autonomous_proposal_detector = CompoundAutonomousProposalDetector::new(self.bytecode.clone());
        let compound_autonomous_proposal_vulnerabilities = compound_autonomous_proposal_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_autonomous_proposal_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_edge_case_detector = CompoundEdgeCaseDetector::new(self.bytecode.clone());
        let compound_edge_case_vulnerabilities = compound_edge_case_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_edge_case_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_governance_detector = CompoundGovernanceDetector::new(self.bytecode.clone());
        let compound_governance_vulnerabilities = compound_governance_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_governance_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_interest_calculation_error_detector = CompoundInterestCalculationErrorDetector::new(self.bytecode.clone());
        let compound_interest_calculation_error_vulnerabilities = compound_interest_calculation_error_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_interest_calculation_error_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_option_nested_exercise_detector = CompoundOptionNestedExerciseDetector::new(self.bytecode.clone());
        let compound_option_nested_exercise_vulnerabilities = compound_option_nested_exercise_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_option_nested_exercise_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_v3_absorption_detector = CompoundV3AbsorptionDetector::new(self.bytecode.clone());
        let compound_v3_absorption_vulnerabilities = compound_v3_absorption_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_v3_absorption_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_v3_base_token_price_manipulation_detector = CompoundV3BaseTokenPriceManipulationDetector::new(self.bytecode.clone());
        let compound_v3_base_token_price_manipulation_vulnerabilities = compound_v3_base_token_price_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_v3_base_token_price_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let compound_v3_liquidation_incentive_detector = CompoundV3LiquidationIncentiveDetector::new(self.bytecode.clone());
        let compound_v3_liquidation_incentive_vulnerabilities = compound_v3_liquidation_incentive_detector.detect_vulnerabilities();
        total_vulnerabilities += compound_v3_liquidation_incentive_vulnerabilities.len() as u32;
        modules_run += 1;

        let compressed_calldata_bomb_detector = CompressedCalldataBombDetector::new(self.bytecode.clone());
        let compressed_calldata_bomb_vulnerabilities = compressed_calldata_bomb_detector.detect_vulnerabilities();
        total_vulnerabilities += compressed_calldata_bomb_vulnerabilities.len() as u32;
        modules_run += 1;

        let compression_bomb_detector = CompressionBombDetector::new(self.bytecode.clone());
        let compression_bomb_vulnerabilities = compression_bomb_detector.detect_vulnerabilities();
        total_vulnerabilities += compression_bomb_vulnerabilities.len() as u32;
        modules_run += 1;

        let concentrated_liquidity_math_detector = ConcentratedLiquidityMathDetector::new(self.bytecode.clone());
        let concentrated_liquidity_math_vulnerabilities = concentrated_liquidity_math_detector.detect_vulnerabilities();
        total_vulnerabilities += concentrated_liquidity_math_vulnerabilities.len() as u32;
        modules_run += 1;

        let concentrated_liquidity_numerical_instability_detector = ConcentratedLiquidityNumericalInstabilityDetector::new(self.bytecode.clone());
        let concentrated_liquidity_numerical_instability_vulnerabilities = concentrated_liquidity_numerical_instability_detector.detect_vulnerabilities();
        total_vulnerabilities += concentrated_liquidity_numerical_instability_vulnerabilities.len() as u32;
        modules_run += 1;

        let concentrated_liquidity_tick_exploit_detector = ConcentratedLiquidityTickExploitDetector::new(self.bytecode.clone());
        let concentrated_liquidity_tick_exploit_vulnerabilities = concentrated_liquidity_tick_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += concentrated_liquidity_tick_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let conditional_order_detector = ConditionalOrderDetector::new(self.bytecode.clone());
        let conditional_order_vulnerabilities = conditional_order_detector.detect_vulnerabilities();
        total_vulnerabilities += conditional_order_vulnerabilities.len() as u32;
        modules_run += 1;

        let constant_product_detector = ConstantProductDetector::new(self.bytecode.clone());
        let constant_product_vulnerabilities = constant_product_detector.detect_vulnerabilities();
        total_vulnerabilities += constant_product_vulnerabilities.len() as u32;
        modules_run += 1;

        let constant_product_overflow_detector = ConstantProductOverflowDetector::new(self.bytecode.clone());
        let constant_product_overflow_vulnerabilities = constant_product_overflow_detector.detect_vulnerabilities();
        total_vulnerabilities += constant_product_overflow_vulnerabilities.len() as u32;
        modules_run += 1;

        let constant_sum_detector = ConstantSumDetector::new(self.bytecode.clone());
        let constant_sum_vulnerabilities = constant_sum_detector.detect_vulnerabilities();
        total_vulnerabilities += constant_sum_vulnerabilities.len() as u32;
        modules_run += 1;

        let constructor_failure_detector = ConstructorFailureDetector::new(self.bytecode.clone());
        let constructor_failure_vulnerabilities = constructor_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += constructor_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let constructor_in_upgradeable_detector = ConstructorInUpgradeableDetector::new(self.bytecode.clone());
        let constructor_in_upgradeable_vulnerabilities = constructor_in_upgradeable_detector.detect_vulnerabilities();
        total_vulnerabilities += constructor_in_upgradeable_vulnerabilities.len() as u32;
        modules_run += 1;

        let constructor_msg_value_detector = ConstructorMsgValueDetector::new(self.bytecode.clone());
        let constructor_msg_value_vulnerabilities = constructor_msg_value_detector.detect_vulnerabilities();
        total_vulnerabilities += constructor_msg_value_vulnerabilities.len() as u32;
        modules_run += 1;

        let constructor_runtime_divergence_detector = ConstructorRuntimeDivergenceDetector::new(self.bytecode.clone());
        let constructor_runtime_divergence_vulnerabilities = constructor_runtime_divergence_detector.detect_vulnerabilities();
        total_vulnerabilities += constructor_runtime_divergence_vulnerabilities.len() as u32;
        modules_run += 1;

        let create2_exploit_detector = CREATE2ExploitDetector::new(self.bytecode.clone());
        let create2_exploit_vulnerabilities = create2_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += create2_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let create2_metamorphic_state_detector = Create2MetamorphicStateDetector::new(self.bytecode.clone());
        let create2_metamorphic_state_vulnerabilities = create2_metamorphic_state_detector.detect_vulnerabilities();
        total_vulnerabilities += create2_metamorphic_state_vulnerabilities.len() as u32;
        modules_run += 1;

        let create2_salt_grinding_detector = Create2SaltGrindingDetector::new(self.bytecode.clone());
        let create2_salt_grinding_vulnerabilities = create2_salt_grinding_detector.detect_vulnerabilities();
        total_vulnerabilities += create2_salt_grinding_vulnerabilities.len() as u32;
        modules_run += 1;

        let create_reentrancy_detector = CreateReentrancyDetector::new(self.bytecode.clone());
        let create_reentrancy_vulnerabilities = create_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += create_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let credit_default_swap_trigger_detector = CreditDefaultSwapTriggerDetector::new(self.bytecode.clone());
        let credit_default_swap_trigger_vulnerabilities = credit_default_swap_trigger_detector.detect_vulnerabilities();
        total_vulnerabilities += credit_default_swap_trigger_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_chain_atomic_swap_failure_detector = CrossChainAtomicSwapFailureDetector::new(self.bytecode.clone());
        let cross_chain_atomic_swap_failure_vulnerabilities = cross_chain_atomic_swap_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_chain_atomic_swap_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_chain_keeper_bypass_detector = CrossChainKeeperBypassDetector::new(self.bytecode.clone());
        let cross_chain_keeper_bypass_vulnerabilities = cross_chain_keeper_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_chain_keeper_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_chain_message_relay_detector = CrossChainMessageRelayDetector::new(self.bytecode.clone());
        let cross_chain_message_relay_vulnerabilities = cross_chain_message_relay_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_chain_message_relay_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_chain_oracle_arbitrage_detector = CrossChainOracleArbitrageDetector::new(self.bytecode.clone());
        let cross_chain_oracle_arbitrage_vulnerabilities = cross_chain_oracle_arbitrage_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_chain_oracle_arbitrage_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_chain_replay_detector = CrossChainReplayDetector::new(self.bytecode.clone());
        let cross_chain_replay_vulnerabilities = cross_chain_replay_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_chain_replay_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_dex_arbitrage_loop_detector = CrossDexArbitrageLoopDetector::new(self.bytecode.clone());
        let cross_dex_arbitrage_loop_vulnerabilities = cross_dex_arbitrage_loop_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_dex_arbitrage_loop_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_domain_intent_atomicity_detector = CrossDomainIntentAtomicityDetector::new(self.bytecode.clone());
        let cross_domain_intent_atomicity_vulnerabilities = cross_domain_intent_atomicity_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_domain_intent_atomicity_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_domain_mev_detector = CrossDomainMEVDetector::new(self.bytecode.clone());
        let cross_domain_mev_vulnerabilities = cross_domain_mev_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_domain_mev_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_domain_web2_web3_detector = CrossDomainWeb2Web3Detector::new(self.bytecode.clone());
        let cross_domain_web2_web3_vulnerabilities = cross_domain_web2_web3_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_domain_web2_web3_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_function_reentrancy_detector = CrossFunctionReentrancyDetector::new(self.bytecode.clone());
        let cross_function_reentrancy_vulnerabilities = cross_function_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_function_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_layer_message_amplification_detector = CrossLayerMessageAmplificationDetector::new(self.bytecode.clone());
        let cross_layer_message_amplification_vulnerabilities = cross_layer_message_amplification_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_layer_message_amplification_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_protocol_mev_coordination_detector = CrossProtocolMevCoordinationDetector::new(self.bytecode.clone());
        let cross_protocol_mev_coordination_vulnerabilities = cross_protocol_mev_coordination_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_protocol_mev_coordination_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_shard_atomic_failure_detector = CrossShardAtomicFailureDetector::new(self.bytecode.clone());
        let cross_shard_atomic_failure_vulnerabilities = cross_shard_atomic_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_shard_atomic_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let cross_slashing_correlation_risk_detector = CrossSlashingCorrelationRiskDetector::new(self.bytecode.clone());
        let cross_slashing_correlation_risk_vulnerabilities = cross_slashing_correlation_risk_detector.detect_vulnerabilities();
        total_vulnerabilities += cross_slashing_correlation_risk_vulnerabilities.len() as u32;
        modules_run += 1;

        let cryptographic_weakness_detector = CryptographicWeaknessDetector::new(self.bytecode.clone());
        let cryptographic_weakness_vulnerabilities = cryptographic_weakness_detector.detect_vulnerabilities();
        total_vulnerabilities += cryptographic_weakness_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_readonly_reentrancy_detector = CurveReadOnlyReentrancyDetector::new(self.bytecode.clone());
        let curve_readonly_reentrancy_vulnerabilities = curve_readonly_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_readonly_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_stableswap_a_ramp_manipulation_detector = CurveStableswapADetector::new(self.bytecode.clone());
        let curve_stableswap_a_ramp_manipulation_vulnerabilities = curve_stableswap_a_ramp_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_stableswap_a_ramp_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_tricrypto_detector = CurveTricryptoDetector::new(self.bytecode.clone());
        let curve_tricrypto_vulnerabilities = curve_tricrypto_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_tricrypto_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_v2_gamma_sandwich_detector = CurveV2GammaSandwichDetector::new(self.bytecode.clone());
        let curve_v2_gamma_sandwich_vulnerabilities = curve_v2_gamma_sandwich_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_v2_gamma_sandwich_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_vyper_pool_bug_detector = CurveVyperPoolBugDetector::new(self.bytecode.clone());
        let curve_vyper_pool_bug_vulnerabilities = curve_vyper_pool_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_vyper_pool_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let curve_vyper_reentrancy_detector = CurveVyperReentrancyDetector::new(self.bytecode.clone());
        let curve_vyper_reentrancy_vulnerabilities = curve_vyper_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += curve_vyper_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let custom_error_selector_collision_detector = CustomErrorSelectorCollisionDetector::new(self.bytecode.clone());
        let custom_error_selector_collision_vulnerabilities = custom_error_selector_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += custom_error_selector_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let da_sampling_vulnerability_detector = DaSamplingVulnerabilityDetector::new(self.bytecode.clone());
        let da_sampling_vulnerability_vulnerabilities = da_sampling_vulnerability_detector.detect_vulnerabilities();
        total_vulnerabilities += da_sampling_vulnerability_vulnerabilities.len() as u32;
        modules_run += 1;

        let deflationary_token_detector = DeflationaryTokenDetector::new(self.bytecode.clone());
        let deflationary_token_vulnerabilities = deflationary_token_detector.detect_vulnerabilities();
        total_vulnerabilities += deflationary_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let delayed_inbox_censorship_detector = DelayedInboxCensorshipDetector::new(self.bytecode.clone());
        let delayed_inbox_censorship_vulnerabilities = delayed_inbox_censorship_detector.detect_vulnerabilities();
        total_vulnerabilities += delayed_inbox_censorship_vulnerabilities.len() as u32;
        modules_run += 1;

        let delegatecall_selector_collision_detector = DelegatecallSelectorCollisionDetector::new(self.bytecode.clone());
        let delegatecall_selector_collision_vulnerabilities = delegatecall_selector_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += delegatecall_selector_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let delegatecall_to_eoa_detector = DelegatecallToEOADetector::new(self.bytecode.clone());
        let delegatecall_to_eoa_vulnerabilities = delegatecall_to_eoa_detector.detect_vulnerabilities();
        total_vulnerabilities += delegatecall_to_eoa_vulnerabilities.len() as u32;
        modules_run += 1;

        let delegated_voting_manipulation_detector = DelegatedVotingManipulationDetector::new(self.bytecode.clone());
        let delegated_voting_manipulation_vulnerabilities = delegated_voting_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += delegated_voting_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let delegation_vulnerability_detector = DelegationVulnerabilityDetector::new(self.bytecode.clone());
        let delegation_vulnerability_vulnerabilities = delegation_vulnerability_detector.detect_vulnerabilities();
        total_vulnerabilities += delegation_vulnerability_vulnerabilities.len() as u32;
        modules_run += 1;

        let dex_aggregator_advanced_detector = DexAggregatorAdvancedDetector::new(self.bytecode.clone());
        let dex_aggregator_advanced_vulnerabilities = dex_aggregator_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += dex_aggregator_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let dia_oracle_source_gaming_detector = DiaOracleSourceGamingDetector::new(self.bytecode.clone());
        let dia_oracle_source_gaming_vulnerabilities = dia_oracle_source_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += dia_oracle_source_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let diamond_storage_collision_detector = DiamondStorageCollisionDetector::new(self.bytecode.clone());
        let diamond_storage_collision_vulnerabilities = diamond_storage_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += diamond_storage_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let digital_option_delta_discontinuity_detector = DigitalOptionDeltaDiscontinuityDetector::new(self.bytecode.clone());
        let digital_option_delta_discontinuity_vulnerabilities = digital_option_delta_discontinuity_detector.detect_vulnerabilities();
        total_vulnerabilities += digital_option_delta_discontinuity_vulnerabilities.len() as u32;
        modules_run += 1;

        let dirty_bytes_bug_detector = DirtyBytesBugDetector::new(self.bytecode.clone());
        let dirty_bytes_bug_vulnerabilities = dirty_bytes_bug_detector.detect_vulnerabilities();
        total_vulnerabilities += dirty_bytes_bug_vulnerabilities.len() as u32;
        modules_run += 1;

        let discrete_log_weakness_detector = DiscreteLogWeaknessDetector::new(self.bytecode.clone());
        let discrete_log_weakness_vulnerabilities = discrete_log_weakness_detector.detect_vulnerabilities();
        total_vulnerabilities += discrete_log_weakness_vulnerabilities.len() as u32;
        modules_run += 1;

        let dispersion_trading_exploit_detector = DispersionTradingExploitDetector::new(self.bytecode.clone());
        let dispersion_trading_exploit_vulnerabilities = dispersion_trading_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += dispersion_trading_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let distributed_validator_key_management_detector = DistributedValidatorKeyManagementDetector::new(self.bytecode.clone());
        let distributed_validator_key_management_vulnerabilities = distributed_validator_key_management_detector.detect_vulnerabilities();
        total_vulnerabilities += distributed_validator_key_management_vulnerabilities.len() as u32;
        modules_run += 1;

        let diva_staking_withdrawal_detector = DivaStakingWithdrawalDetector::new(self.bytecode.clone());
        let diva_staking_withdrawal_vulnerabilities = diva_staking_withdrawal_detector.detect_vulnerabilities();
        total_vulnerabilities += diva_staking_withdrawal_vulnerabilities.len() as u32;
        modules_run += 1;

        let donate_to_pool_attack_detector = DonateToPoolAttackDetector::new(self.bytecode.clone());
        let donate_to_pool_attack_vulnerabilities = donate_to_pool_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += donate_to_pool_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let donation_attack_advanced_detector = DonationAttackAdvancedDetector::new(self.bytecode.clone());
        let donation_attack_advanced_vulnerabilities = donation_attack_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += donation_attack_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let donation_attack_detector = DonationAttackDetector::new(self.bytecode.clone());
        let donation_attack_vulnerabilities = donation_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += donation_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let double_entry_point_token_detector = DoubleEntryPointTokenDetector::new(self.bytecode.clone());
        let double_entry_point_token_vulnerabilities = double_entry_point_token_detector.detect_vulnerabilities();
        total_vulnerabilities += double_entry_point_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let double_initialization_attack_detector = DoubleInitializationAttackDetector::new(self.bytecode.clone());
        let double_initialization_attack_vulnerabilities = double_initialization_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += double_initialization_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let dual_state_exploitation_detector = DualStateExploitationDetector::new(self.bytecode.clone());
        let dual_state_exploitation_vulnerabilities = dual_state_exploitation_detector.detect_vulnerabilities();
        total_vulnerabilities += dual_state_exploitation_vulnerabilities.len() as u32;
        modules_run += 1;

        let duration_convexity_exploit_detector = DurationConvexityExploitDetector::new(self.bytecode.clone());
        let duration_convexity_exploit_vulnerabilities = duration_convexity_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += duration_convexity_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let dust_attack_detector = DustAttackDetector::new(self.bytecode.clone());
        let dust_attack_vulnerabilities = dust_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += dust_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let dvt_split_brain_detector = DvtSplitBrainDetector::new(self.bytecode.clone());
        let dvt_split_brain_vulnerabilities = dvt_split_brain_detector.detect_vulnerabilities();
        total_vulnerabilities += dvt_split_brain_vulnerabilities.len() as u32;
        modules_run += 1;

        let dvt_validator_offline_slashing_detector = DvtValidatorOfflineSlashingDetector::new(self.bytecode.clone());
        let dvt_validator_offline_slashing_vulnerabilities = dvt_validator_offline_slashing_detector.detect_vulnerabilities();
        total_vulnerabilities += dvt_validator_offline_slashing_vulnerabilities.len() as u32;
        modules_run += 1;

        let dynamic_fee_amm_gaming_detector = DynamicFeeAMMGamingDetector::new(self.bytecode.clone());
        let dynamic_fee_amm_gaming_vulnerabilities = dynamic_fee_amm_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += dynamic_fee_amm_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let dynamic_nft_metadata_detector = DynamicNftMetadataDetector::new(self.bytecode.clone());
        let dynamic_nft_metadata_vulnerabilities = dynamic_nft_metadata_detector.detect_vulnerabilities();
        total_vulnerabilities += dynamic_nft_metadata_vulnerabilities.len() as u32;
        modules_run += 1;

        let dynamic_nft_metadata_race_detector = DynamicNftMetadataRaceDetector::new(self.bytecode.clone());
        let dynamic_nft_metadata_race_vulnerabilities = dynamic_nft_metadata_race_detector.detect_vulnerabilities();
        total_vulnerabilities += dynamic_nft_metadata_race_vulnerabilities.len() as u32;
        modules_run += 1;

        let dynamic_nft_state_exploit_detector = DynamicNftStateExploitDetector::new(self.bytecode.clone());
        let dynamic_nft_state_exploit_vulnerabilities = dynamic_nft_state_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += dynamic_nft_state_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let ecrecover_zero_address_detector = EcrecoverZeroAddressDetector::new(self.bytecode.clone());
        let ecrecover_zero_address_vulnerabilities = ecrecover_zero_address_detector.detect_vulnerabilities();
        total_vulnerabilities += ecrecover_zero_address_vulnerabilities.len() as u32;
        modules_run += 1;

        let efficient_market_violation_detector = EfficientMarketViolationDetector::new(self.bytecode.clone());
        let efficient_market_violation_vulnerabilities = efficient_market_violation_detector.detect_vulnerabilities();
        total_vulnerabilities += efficient_market_violation_vulnerabilities.len() as u32;
        modules_run += 1;

        let eigenda_blob_withholding_detector = EigendaBlobWithholdingDetector::new(self.bytecode.clone());
        let eigenda_blob_withholding_vulnerabilities = eigenda_blob_withholding_detector.detect_vulnerabilities();
        total_vulnerabilities += eigenda_blob_withholding_vulnerabilities.len() as u32;
        modules_run += 1;

        let eigenlayer_avs_detector = EigenlayerAvsDetector::new(self.bytecode.clone());
        let eigenlayer_avs_vulnerabilities = eigenlayer_avs_detector.detect_vulnerabilities();
        total_vulnerabilities += eigenlayer_avs_vulnerabilities.len() as u32;
        modules_run += 1;

        let eigenlayer_avs_slashing_detector = EigenlayerAvsSlashingDetector::new(self.bytecode.clone());
        let eigenlayer_avs_slashing_vulnerabilities = eigenlayer_avs_slashing_detector.detect_vulnerabilities();
        total_vulnerabilities += eigenlayer_avs_slashing_vulnerabilities.len() as u32;
        modules_run += 1;

        let eigenlayer_slashing_veto_detector = EigenlayerSlashingVetoDetector::new(self.bytecode.clone());
        let eigenlayer_slashing_veto_vulnerabilities = eigenlayer_slashing_veto_detector.detect_vulnerabilities();
        total_vulnerabilities += eigenlayer_slashing_veto_vulnerabilities.len() as u32;
        modules_run += 1;

        let eigenpod_withdrawal_proof_detector = EigenpodWithdrawalProofDetector::new(self.bytecode.clone());
        let eigenpod_withdrawal_proof_vulnerabilities = eigenpod_withdrawal_proof_detector.detect_vulnerabilities();
        total_vulnerabilities += eigenpod_withdrawal_proof_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip1167_minimal_proxy_detector = Eip1167MinimalProxyDetector::new(self.bytecode.clone());
        let eip1167_minimal_proxy_vulnerabilities = eip1167_minimal_proxy_detector.detect_vulnerabilities();
        total_vulnerabilities += eip1167_minimal_proxy_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip1271_recursive_validation_detector = Eip1271RecursiveValidationDetector::new(self.bytecode.clone());
        let eip1271_recursive_validation_vulnerabilities = eip1271_recursive_validation_detector.detect_vulnerabilities();
        total_vulnerabilities += eip1271_recursive_validation_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip1559_basefee_advanced_detector = EIP1559BaseFeeAdvancedDetector::new(self.bytecode.clone());
        let eip1559_basefee_advanced_vulnerabilities = eip1559_basefee_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += eip1559_basefee_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip1967_collision_detector = EIP1967CollisionDetector::new(self.bytecode.clone());
        let eip1967_collision_vulnerabilities = eip1967_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += eip1967_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip1967_proxy_confusion_detector = Eip1967ProxyConfusionDetector::new(self.bytecode.clone());
        let eip1967_proxy_confusion_vulnerabilities = eip1967_proxy_confusion_detector.detect_vulnerabilities();
        total_vulnerabilities += eip1967_proxy_confusion_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip2930_access_list_detector = Eip2930AccessListDetector::new(self.bytecode.clone());
        let eip2930_access_list_vulnerabilities = eip2930_access_list_detector.detect_vulnerabilities();
        total_vulnerabilities += eip2930_access_list_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip3074_auth_detector = EIP3074Detector::new(self.bytecode.clone());
        let eip3074_auth_vulnerabilities = eip3074_auth_detector.detect_vulnerabilities();
        total_vulnerabilities += eip3074_auth_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip4758_selfdestruct_deactivation_detector = Eip4758SelfdestructDeactivationDetector::new(self.bytecode.clone());
        let eip4758_selfdestruct_deactivation_vulnerabilities = eip4758_selfdestruct_deactivation_detector.detect_vulnerabilities();
        total_vulnerabilities += eip4758_selfdestruct_deactivation_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip6780_selfdestruct_detector = EIP6780SelfdestructDetector::new(self.bytecode.clone());
        let eip6780_selfdestruct_vulnerabilities = eip6780_selfdestruct_detector.detect_vulnerabilities();
        total_vulnerabilities += eip6780_selfdestruct_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip712_domain_chainid_missing_detector = Eip712DomainChainidMissingDetector::new(self.bytecode.clone());
        let eip712_domain_chainid_missing_vulnerabilities = eip712_domain_chainid_missing_detector.detect_vulnerabilities();
        total_vulnerabilities += eip712_domain_chainid_missing_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip712_typed_data_detector = Eip712TypedDataDetector::new(self.bytecode.clone());
        let eip712_typed_data_vulnerabilities = eip712_typed_data_detector.detect_vulnerabilities();
        total_vulnerabilities += eip712_typed_data_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip7514_validator_churn_bypass_detector = Eip7514ValidatorChurnBypassDetector::new(self.bytecode.clone());
        let eip7514_validator_churn_bypass_vulnerabilities = eip7514_validator_churn_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += eip7514_validator_churn_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip7702_delegation_detector = Eip7702DelegationDetector::new(self.bytecode.clone());
        let eip7702_delegation_vulnerabilities = eip7702_delegation_detector.detect_vulnerabilities();
        total_vulnerabilities += eip7702_delegation_vulnerabilities.len() as u32;
        modules_run += 1;

        let eip7702_native_aa_conversion_detector = Eip7702NativeAaConversionDetector::new(self.bytecode.clone());
        let eip7702_native_aa_conversion_vulnerabilities = eip7702_native_aa_conversion_detector.detect_vulnerabilities();
        total_vulnerabilities += eip7702_native_aa_conversion_vulnerabilities.len() as u32;
        modules_run += 1;

        let elastic_supply_vault_manipulation_detector = ElasticSupplyVaultManipulationDetector::new(self.bytecode.clone());
        let elastic_supply_vault_manipulation_vulnerabilities = elastic_supply_vault_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += elastic_supply_vault_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let element_fixed_rates_detector = ElementFixedRatesDetector::new(self.bytecode.clone());
        let element_fixed_rates_vulnerabilities = element_fixed_rates_detector.detect_vulnerabilities();
        total_vulnerabilities += element_fixed_rates_vulnerabilities.len() as u32;
        modules_run += 1;

        let elliptic_curve_twist_detector = EllipticCurveTwistDetector::new(self.bytecode.clone());
        let elliptic_curve_twist_vulnerabilities = elliptic_curve_twist_detector.detect_vulnerabilities();
        total_vulnerabilities += elliptic_curve_twist_vulnerabilities.len() as u32;
        modules_run += 1;

        let embedded_wallet_sdk_detector = EmbeddedWalletSDKDetector::new(self.bytecode.clone());
        let embedded_wallet_sdk_vulnerabilities = embedded_wallet_sdk_detector.detect_vulnerabilities();
        total_vulnerabilities += embedded_wallet_sdk_vulnerabilities.len() as u32;
        modules_run += 1;

        let emergency_function_abuse_detector = EmergencyFunctionAbuseDetector::new(self.bytecode.clone());
        let emergency_function_abuse_vulnerabilities = emergency_function_abuse_detector.detect_vulnerabilities();
        total_vulnerabilities += emergency_function_abuse_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc1271_contract_signature_detector = Erc1271ContractSignatureDetector::new(self.bytecode.clone());
        let erc1271_contract_signature_vulnerabilities = erc1271_contract_signature_detector.detect_vulnerabilities();
        total_vulnerabilities += erc1271_contract_signature_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc1363_payable_token_detector = Erc1363PayableTokenDetector::new(self.bytecode.clone());
        let erc1363_payable_token_vulnerabilities = erc1363_payable_token_detector.detect_vulnerabilities();
        total_vulnerabilities += erc1363_payable_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc1400_security_token_detector = Erc1400SecurityTokenDetector::new(self.bytecode.clone());
        let erc1400_security_token_vulnerabilities = erc1400_security_token_detector.detect_vulnerabilities();
        total_vulnerabilities += erc1400_security_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc1404_restricted_token_detector = Erc1404RestrictedTokenDetector::new(self.bytecode.clone());
        let erc1404_restricted_token_vulnerabilities = erc1404_restricted_token_detector.detect_vulnerabilities();
        total_vulnerabilities += erc1404_restricted_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc165_interface_detector = Erc165InterfaceDetector::new(self.bytecode.clone());
        let erc165_interface_vulnerabilities = erc165_interface_detector.detect_vulnerabilities();
        total_vulnerabilities += erc165_interface_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc20_approve_race_condition_detector = Erc20ApproveRaceConditionDetector::new(self.bytecode.clone());
        let erc20_approve_race_condition_vulnerabilities = erc20_approve_race_condition_detector.detect_vulnerabilities();
        total_vulnerabilities += erc20_approve_race_condition_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc20_transfer_return_unchecked_detector = Erc20TransferReturnUncheckedDetector::new(self.bytecode.clone());
        let erc20_transfer_return_unchecked_vulnerabilities = erc20_transfer_return_unchecked_detector.detect_vulnerabilities();
        total_vulnerabilities += erc20_transfer_return_unchecked_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc2222_funds_distribution_detector = Erc2222FundsDistributionDetector::new(self.bytecode.clone());
        let erc2222_funds_distribution_vulnerabilities = erc2222_funds_distribution_detector.detect_vulnerabilities();
        total_vulnerabilities += erc2222_funds_distribution_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc2612_permit_frontrun_detector = Erc2612PermitFrontrunDetector::new(self.bytecode.clone());
        let erc2612_permit_frontrun_vulnerabilities = erc2612_permit_frontrun_detector.detect_vulnerabilities();
        total_vulnerabilities += erc2612_permit_frontrun_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc2771_meta_transaction_detector = Erc2771MetaTransactionDetector::new(self.bytecode.clone());
        let erc2771_meta_transaction_vulnerabilities = erc2771_meta_transaction_detector.detect_vulnerabilities();
        total_vulnerabilities += erc2771_meta_transaction_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc2981_royalty_bypass_detector = Erc2981RoyaltyBypassDetector::new(self.bytecode.clone());
        let erc2981_royalty_bypass_vulnerabilities = erc2981_royalty_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += erc2981_royalty_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc3156_flash_loan_detector = Erc3156FlashLoanDetector::new(self.bytecode.clone());
        let erc3156_flash_loan_vulnerabilities = erc3156_flash_loan_detector.detect_vulnerabilities();
        total_vulnerabilities += erc3156_flash_loan_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc3475_multi_class_bond_detector = Erc3475MultiClassBondDetector::new(self.bytecode.clone());
        let erc3475_multi_class_bond_vulnerabilities = erc3475_multi_class_bond_detector.detect_vulnerabilities();
        total_vulnerabilities += erc3475_multi_class_bond_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc404_detector = Erc404Detector::new(self.bytecode.clone());
        let erc404_vulnerabilities = erc404_detector.detect_vulnerabilities();
        total_vulnerabilities += erc404_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_aggregator_detector = Erc4337AggregatorDetector::new(self.bytecode.clone());
        let erc4337_aggregator_vulnerabilities = erc4337_aggregator_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_aggregator_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_cross_chain_replay_detector = ERC4337CrossChainReplayDetector::new(self.bytecode.clone());
        let erc4337_cross_chain_replay_vulnerabilities = erc4337_cross_chain_replay_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_cross_chain_replay_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_init_code_frontrun_detector = ERC4337InitCodeFrontrunDetector::new(self.bytecode.clone());
        let erc4337_init_code_frontrun_vulnerabilities = erc4337_init_code_frontrun_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_init_code_frontrun_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_paymaster_detector = Erc4337PaymasterDetector::new(self.bytecode.clone());
        let erc4337_paymaster_vulnerabilities = erc4337_paymaster_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_paymaster_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_paymaster_token_rate_manipulation_detector = ERC4337PaymasterTokenRateManipulationDetector::new(self.bytecode.clone());
        let erc4337_paymaster_token_rate_manipulation_vulnerabilities = erc4337_paymaster_token_rate_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_paymaster_token_rate_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_signature_aggregation_griefing_detector = ERC4337SignatureAggregationGriefingDetector::new(self.bytecode.clone());
        let erc4337_signature_aggregation_griefing_vulnerabilities = erc4337_signature_aggregation_griefing_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_signature_aggregation_griefing_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4337_storage_collision_detector = Erc4337StorageCollisionDetector::new(self.bytecode.clone());
        let erc4337_storage_collision_vulnerabilities = erc4337_storage_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4337_storage_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4524_safer_erc20_detector = Erc4524SaferErc20Detector::new(self.bytecode.clone());
        let erc4524_safer_erc20_vulnerabilities = erc4524_safer_erc20_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4524_safer_erc20_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4626_inflation_attack_detector = Erc4626InflationAttackDetector::new(self.bytecode.clone());
        let erc4626_inflation_attack_vulnerabilities = erc4626_inflation_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4626_inflation_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4626_inflation_fee_on_transfer_detector = ERC4626InflationFeeDetector::new(self.bytecode.clone());
        let erc4626_inflation_fee_on_transfer_vulnerabilities = erc4626_inflation_fee_on_transfer_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4626_inflation_fee_on_transfer_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4626_rounding_exploit_detector = ERC4626RoundingExploitDetector::new(self.bytecode.clone());
        let erc4626_rounding_exploit_vulnerabilities = erc4626_rounding_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4626_rounding_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4626_vault_detector = Erc4626VaultDetector::new(self.bytecode.clone());
        let erc4626_vault_vulnerabilities = erc4626_vault_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4626_vault_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4906_metadata_update_detector = Erc4906MetadataUpdateDetector::new(self.bytecode.clone());
        let erc4906_metadata_update_vulnerabilities = erc4906_metadata_update_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4906_metadata_update_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc4907_rental_rights_overlap_detector = Erc4907RentalRightsOverlapDetector::new(self.bytecode.clone());
        let erc4907_rental_rights_overlap_vulnerabilities = erc4907_rental_rights_overlap_detector.detect_vulnerabilities();
        total_vulnerabilities += erc4907_rental_rights_overlap_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5058_lockable_nft_detector = Erc5058LockableNftDetector::new(self.bytecode.clone());
        let erc5058_lockable_nft_vulnerabilities = erc5058_lockable_nft_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5058_lockable_nft_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5114_soulbound_badge_detector = Erc5114SoulboundBadgeDetector::new(self.bytecode.clone());
        let erc5114_soulbound_badge_vulnerabilities = erc5114_soulbound_badge_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5114_soulbound_badge_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5169_token_metadata_detector = Erc5169TokenMetadataDetector::new(self.bytecode.clone());
        let erc5169_token_metadata_vulnerabilities = erc5169_token_metadata_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5169_token_metadata_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5189_endorser_detector = Erc5189EndorserDetector::new(self.bytecode.clone());
        let erc5189_endorser_vulnerabilities = erc5189_endorser_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5189_endorser_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5192_sbt_transfer_detector = Erc5192SbtTransferDetector::new(self.bytecode.clone());
        let erc5192_sbt_transfer_vulnerabilities = erc5192_sbt_transfer_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5192_sbt_transfer_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5192_soulbound_bypass_detector = Erc5192SoulboundBypassDetector::new(self.bytecode.clone());
        let erc5192_soulbound_bypass_vulnerabilities = erc5192_soulbound_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5192_soulbound_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc5334_eip1155_extension_detector = Erc5334Eip1155ExtensionDetector::new(self.bytecode.clone());
        let erc5334_eip1155_extension_vulnerabilities = erc5334_eip1155_extension_detector.detect_vulnerabilities();
        total_vulnerabilities += erc5334_eip1155_extension_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6150_hierarchical_nft_detector = Erc6150HierarchicalNftDetector::new(self.bytecode.clone());
        let erc6150_hierarchical_nft_vulnerabilities = erc6150_hierarchical_nft_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6150_hierarchical_nft_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6492_signature_validator_detector = Erc6492SignatureValidatorDetector::new(self.bytecode.clone());
        let erc6492_signature_validator_vulnerabilities = erc6492_signature_validator_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6492_signature_validator_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6551_token_bound_accounts_detector = Erc6551TokenBoundAccountsDetector::new(self.bytecode.clone());
        let erc6551_token_bound_accounts_vulnerabilities = erc6551_token_bound_accounts_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6551_token_bound_accounts_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6900_module_security_detector = Erc6900ModuleSecurityDetector::new(self.bytecode.clone());
        let erc6900_module_security_vulnerabilities = erc6900_module_security_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6900_module_security_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6900_plugin_detector = Erc6900PluginDetector::new(self.bytecode.clone());
        let erc6900_plugin_vulnerabilities = erc6900_plugin_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6900_plugin_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc6909_detector = ERC6909Detector::new(self.bytecode.clone());
        let erc6909_vulnerabilities = erc6909_detector.detect_vulnerabilities();
        total_vulnerabilities += erc6909_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7007_ai_nft_detector = Erc7007AiNftDetector::new(self.bytecode.clone());
        let erc7007_ai_nft_vulnerabilities = erc7007_ai_nft_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7007_ai_nft_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc721_enumeration_gas_detector = ERC721EnumerationGasDetector::new(self.bytecode.clone());
        let erc721_enumeration_gas_vulnerabilities = erc721_enumeration_gas_detector.detect_vulnerabilities();
        total_vulnerabilities += erc721_enumeration_gas_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc721_onerc721received_missing_detector = Erc721Onerc721receivedMissingDetector::new(self.bytecode.clone());
        let erc721_onerc721received_missing_vulnerabilities = erc721_onerc721received_missing_detector.detect_vulnerabilities();
        total_vulnerabilities += erc721_onerc721received_missing_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc721a_detector = Erc721aDetector::new(self.bytecode.clone());
        let erc721a_vulnerabilities = erc721a_detector.detect_vulnerabilities();
        total_vulnerabilities += erc721a_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7281_tba_detector = ERC7281TBADetector::new(self.bytecode.clone());
        let erc7281_tba_vulnerabilities = erc7281_tba_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7281_tba_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7303_progressive_decentralization_detector = Erc7303ProgressiveDecentralizationDetector::new(self.bytecode.clone());
        let erc7303_progressive_decentralization_vulnerabilities = erc7303_progressive_decentralization_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7303_progressive_decentralization_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7401_parent_governed_nft_detector = Erc7401ParentGovernedNftDetector::new(self.bytecode.clone());
        let erc7401_parent_governed_nft_vulnerabilities = erc7401_parent_governed_nft_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7401_parent_governed_nft_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7412_pull_oracle_detector = Erc7412PullOracleDetector::new(self.bytecode.clone());
        let erc7412_pull_oracle_vulnerabilities = erc7412_pull_oracle_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7412_pull_oracle_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7498_nft_redeemable_detector = Erc7498NftRedeemableDetector::new(self.bytecode.clone());
        let erc7498_nft_redeemable_vulnerabilities = erc7498_nft_redeemable_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7498_nft_redeemable_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7518_dynamic_traits_detector = Erc7518DynamicTraitsDetector::new(self.bytecode.clone());
        let erc7518_dynamic_traits_vulnerabilities = erc7518_dynamic_traits_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7518_dynamic_traits_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7540_async_vault_detector = Erc7540AsyncVaultDetector::new(self.bytecode.clone());
        let erc7540_async_vault_vulnerabilities = erc7540_async_vault_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7540_async_vault_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7579_modular_account_detector = ERC7579Detector::new(self.bytecode.clone());
        let erc7579_modular_account_vulnerabilities = erc7579_modular_account_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7579_modular_account_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7579_module_conflict_detector = Erc7579ModuleConflictDetector::new(self.bytecode.clone());
        let erc7579_module_conflict_vulnerabilities = erc7579_module_conflict_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7579_module_conflict_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7621_basket_token_detector = Erc7621BasketTokenDetector::new(self.bytecode.clone());
        let erc7621_basket_token_vulnerabilities = erc7621_basket_token_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7621_basket_token_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7641_revenue_distribution_detector = ERC7641RevenueDistributionDetector::new(self.bytecode.clone());
        let erc7641_revenue_distribution_vulnerabilities = erc7641_revenue_distribution_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7641_revenue_distribution_vulnerabilities.len() as u32;
        modules_run += 1;

        let erc7677_paymaster_detector = Erc7677PaymasterDetector::new(self.bytecode.clone());
        let erc7677_paymaster_vulnerabilities = erc7677_paymaster_detector.detect_vulnerabilities();
        total_vulnerabilities += erc7677_paymaster_vulnerabilities.len() as u32;
        modules_run += 1;

        let escape_hatch_dos_detector = EscapeHatchDosDetector::new(self.bytecode.clone());
        let escape_hatch_dos_vulnerabilities = escape_hatch_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += escape_hatch_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let espresso_shared_sequencer_detector = EspressoSharedSequencerDetector::new(self.bytecode.clone());
        let espresso_shared_sequencer_vulnerabilities = espresso_shared_sequencer_detector.detect_vulnerabilities();
        total_vulnerabilities += espresso_shared_sequencer_vulnerabilities.len() as u32;
        modules_run += 1;

        let eth_send_failure_detector = EthSendFailureDetector::new(self.bytecode.clone());
        let eth_send_failure_vulnerabilities = eth_send_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += eth_send_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let ethena_usde_detector = EthenaUSDeDetector::new(self.bytecode.clone());
        let ethena_usde_vulnerabilities = ethena_usde_detector.detect_vulnerabilities();
        total_vulnerabilities += ethena_usde_vulnerabilities.len() as u32;
        modules_run += 1;

        let ethos_reserve_liquidation_detector = EthosReserveLiquidationDetector::new(self.bytecode.clone());
        let ethos_reserve_liquidation_vulnerabilities = ethos_reserve_liquidation_detector.detect_vulnerabilities();
        total_vulnerabilities += ethos_reserve_liquidation_vulnerabilities.len() as u32;
        modules_run += 1;

        let euler_donation_attack_detector = EulerDonationAttackDetector::new(self.bytecode.clone());
        let euler_donation_attack_vulnerabilities = euler_donation_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += euler_donation_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let euler_etoken_health_factor_detector = EulerEtokenHealthFactorDetector::new(self.bytecode.clone());
        let euler_etoken_health_factor_vulnerabilities = euler_etoken_health_factor_detector.detect_vulnerabilities();
        total_vulnerabilities += euler_etoken_health_factor_vulnerabilities.len() as u32;
        modules_run += 1;

        let euler_etoken_liquidation_detector = EulerETokenLiquidationDetector::new(self.bytecode.clone());
        let euler_etoken_liquidation_vulnerabilities = euler_etoken_liquidation_detector.detect_vulnerabilities();
        total_vulnerabilities += euler_etoken_liquidation_vulnerabilities.len() as u32;
        modules_run += 1;

        let event_parameter_spoofing_detector = EventParameterSpoofingDetector::new(self.bytecode.clone());
        let event_parameter_spoofing_vulnerabilities = event_parameter_spoofing_detector.detect_vulnerabilities();
        total_vulnerabilities += event_parameter_spoofing_vulnerabilities.len() as u32;
        modules_run += 1;

        let evm_object_format_detector = EvmObjectFormatDetector::new(self.bytecode.clone());
        let evm_object_format_vulnerabilities = evm_object_format_detector.detect_vulnerabilities();
        total_vulnerabilities += evm_object_format_vulnerabilities.len() as u32;
        modules_run += 1;

        let exactly_protocol_detector = ExactlyProtocolDetector::new(self.bytecode.clone());
        let exactly_protocol_vulnerabilities = exactly_protocol_detector.detect_vulnerabilities();
        total_vulnerabilities += exactly_protocol_vulnerabilities.len() as u32;
        modules_run += 1;

        let exp_taylor_overflow_detector = ExpTaylorOverflowDetector::new(self.bytecode.clone());
        let exp_taylor_overflow_vulnerabilities = exp_taylor_overflow_detector.detect_vulnerabilities();
        total_vulnerabilities += exp_taylor_overflow_vulnerabilities.len() as u32;
        modules_run += 1;

        let extcodesize_bypass_detector = ExtcodesizeBypassDetector::new(self.bytecode.clone());
        let extcodesize_bypass_vulnerabilities = extcodesize_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += extcodesize_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let fallback_receive_ambiguity_detector = FallbackReceiveAmbiguityDetector::new(self.bytecode.clone());
        let fallback_receive_ambiguity_vulnerabilities = fallback_receive_ambiguity_detector.detect_vulnerabilities();
        total_vulnerabilities += fallback_receive_ambiguity_vulnerabilities.len() as u32;
        modules_run += 1;

        let fallback_receive_exploitation_detector = FallbackReceiveExploitationDetector::new(self.bytecode.clone());
        let fallback_receive_exploitation_vulnerabilities = fallback_receive_exploitation_detector.detect_vulnerabilities();
        total_vulnerabilities += fallback_receive_exploitation_vulnerabilities.len() as u32;
        modules_run += 1;

        let fee_model_breaking_point_detector = FeeModelBreakingPointDetector::new(self.bytecode.clone());
        let fee_model_breaking_point_vulnerabilities = fee_model_breaking_point_detector.detect_vulnerabilities();
        total_vulnerabilities += fee_model_breaking_point_vulnerabilities.len() as u32;
        modules_run += 1;

        let fhe_computation_detector = FheComputationDetector::new(self.bytecode.clone());
        let fhe_computation_vulnerabilities = fhe_computation_detector.detect_vulnerabilities();
        total_vulnerabilities += fhe_computation_vulnerabilities.len() as u32;
        modules_run += 1;

        let fhe_sidechannel_detector = FheSidechannelDetector::new(self.bytecode.clone());
        let fhe_sidechannel_vulnerabilities = fhe_sidechannel_detector.detect_vulnerabilities();
        total_vulnerabilities += fhe_sidechannel_vulnerabilities.len() as u32;
        modules_run += 1;

        let first_depositor_attack_detector = FirstDepositorAttackDetector::new(self.bytecode.clone());
        let mut first_depositor_vulnerabilities = first_depositor_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += first_depositor_vulnerabilities.len() as u32;
        modules_run += 1;

        let fixed_point_arithmetic_detector = FixedPointArithmeticDetector::new(self.bytecode.clone());
        let fixed_point_arithmetic_vulnerabilities = fixed_point_arithmetic_detector.detect_vulnerabilities();
        total_vulnerabilities += fixed_point_arithmetic_vulnerabilities.len() as u32;
        modules_run += 1;

        let fixed_point_arithmetic_drift_detector = FixedPointArithmeticDriftDetector::new(self.bytecode.clone());
        let fixed_point_arithmetic_drift_vulnerabilities = fixed_point_arithmetic_drift_detector.detect_vulnerabilities();
        total_vulnerabilities += fixed_point_arithmetic_drift_vulnerabilities.len() as u32;
        modules_run += 1;

        let fixed_point_math_truncation_detector = FixedPointMathTruncationDetector::new(self.bytecode.clone());
        let fixed_point_math_truncation_vulnerabilities = fixed_point_math_truncation_detector.detect_vulnerabilities();
        total_vulnerabilities += fixed_point_math_truncation_vulnerabilities.len() as u32;
        modules_run += 1;

        let fixed_point_nonexistence_detector = FixedPointNonExistenceDetector::new(self.bytecode.clone());
        let fixed_point_nonexistence_vulnerabilities = fixed_point_nonexistence_detector.detect_vulnerabilities();
        total_vulnerabilities += fixed_point_nonexistence_vulnerabilities.len() as u32;
        modules_run += 1;

        let fixed_rate_lending_detector = FixedRateLendingDetector::new(self.bytecode.clone());
        let fixed_rate_lending_vulnerabilities = fixed_rate_lending_detector.detect_vulnerabilities();
        total_vulnerabilities += fixed_rate_lending_vulnerabilities.len() as u32;
        modules_run += 1;

        let flash_loan_voting_detector = FlashLoanVotingDetector::new(self.bytecode.clone());
        let flash_loan_voting_vulnerabilities = flash_loan_voting_detector.detect_vulnerabilities();
        total_vulnerabilities += flash_loan_voting_vulnerabilities.len() as u32;
        modules_run += 1;

        let flash_mint_provider_detector = FlashMintProviderDetector::new(self.bytecode.clone());
        let flash_mint_provider_vulnerabilities = flash_mint_provider_detector.detect_vulnerabilities();
        total_vulnerabilities += flash_mint_provider_vulnerabilities.len() as u32;
        modules_run += 1;

        let flashbots_bundle_analysis_detector = FlashbotsBundleAnalysisDetector::new(self.bytecode.clone());
        let flashbots_bundle_analysis_vulnerabilities = flashbots_bundle_analysis_detector.detect_vulnerabilities();
        total_vulnerabilities += flashbots_bundle_analysis_vulnerabilities.len() as u32;
        modules_run += 1;

        let flashbots_mevm_detector = FlashbotsMevmDetector::new(self.bytecode.clone());
        let flashbots_mevm_vulnerabilities = flashbots_mevm_detector.detect_vulnerabilities();
        total_vulnerabilities += flashbots_mevm_vulnerabilities.len() as u32;
        modules_run += 1;

        let floating_point_emulation_detector = FloatingPointEmulationDetector::new(self.bytecode.clone());
        let floating_point_emulation_vulnerabilities = floating_point_emulation_detector.detect_vulnerabilities();
        total_vulnerabilities += floating_point_emulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let floating_pragma_detector = FloatingPragmaDetector::new(self.bytecode.clone());
        let floating_pragma_vulnerabilities = floating_pragma_detector.detect_vulnerabilities();
        total_vulnerabilities += floating_pragma_vulnerabilities.len() as u32;
        modules_run += 1;

        let flp_impossibility_workaround_detector = FLPImpossibilityWorkaroundDetector::new(self.bytecode.clone());
        let flp_impossibility_workaround_vulnerabilities = flp_impossibility_workaround_detector.detect_vulnerabilities();
        total_vulnerabilities += flp_impossibility_workaround_vulnerabilities.len() as u32;
        modules_run += 1;

        let flux_protocol_averaging_detector = FluxProtocolAveragingDetector::new(self.bytecode.clone());
        let flux_protocol_averaging_vulnerabilities = flux_protocol_averaging_detector.detect_vulnerabilities();
        total_vulnerabilities += flux_protocol_averaging_vulnerabilities.len() as u32;
        modules_run += 1;

        let forced_ether_reception_detector = ForcedEtherReceptionDetector::new(self.bytecode.clone());
        let forced_ether_reception_vulnerabilities = forced_ether_reception_detector.detect_vulnerabilities();
        total_vulnerabilities += forced_ether_reception_vulnerabilities.len() as u32;
        modules_run += 1;

        let forced_transaction_censorship_detector = ForcedTransactionCensorshipDetector::new(self.bytecode.clone());
        let forced_transaction_censorship_vulnerabilities = forced_transaction_censorship_detector.detect_vulnerabilities();
        total_vulnerabilities += forced_transaction_censorship_vulnerabilities.len() as u32;
        modules_run += 1;

        let forced_transaction_detector = ForcedTransactionDetector::new(self.bytecode.clone());
        let forced_transaction_vulnerabilities = forced_transaction_detector.detect_vulnerabilities();
        total_vulnerabilities += forced_transaction_vulnerabilities.len() as u32;
        modules_run += 1;

        let fractal_recursion_bomb_detector = FractalRecursionBombDetector::new(self.bytecode.clone());
        let fractal_recursion_bomb_vulnerabilities = fractal_recursion_bomb_detector.detect_vulnerabilities();
        total_vulnerabilities += fractal_recursion_bomb_vulnerabilities.len() as u32;
        modules_run += 1;

        let framing_effect_detector = FramingEffectDetector::new(self.bytecode.clone());
        let framing_effect_vulnerabilities = framing_effect_detector.detect_vulnerabilities();
        total_vulnerabilities += framing_effect_vulnerabilities.len() as u32;
        modules_run += 1;

        let fraud_proof_griefing_detector = FraudProofGriefingDetector::new(self.bytecode.clone());
        let fraud_proof_griefing_vulnerabilities = fraud_proof_griefing_detector.detect_vulnerabilities();
        total_vulnerabilities += fraud_proof_griefing_vulnerabilities.len() as u32;
        modules_run += 1;

        let fraud_proof_timeout_detector = FraudProofTimeoutDetector::new(self.bytecode.clone());
        let fraud_proof_timeout_vulnerabilities = fraud_proof_timeout_detector.detect_vulnerabilities();
        total_vulnerabilities += fraud_proof_timeout_vulnerabilities.len() as u32;
        modules_run += 1;

        let frax_frxeth_dual_oracle_detector = FraxFrxethDualOracleDetector::new(self.bytecode.clone());
        let frax_frxeth_dual_oracle_vulnerabilities = frax_frxeth_dual_oracle_detector.detect_vulnerabilities();
        total_vulnerabilities += frax_frxeth_dual_oracle_vulnerabilities.len() as u32;
        modules_run += 1;

        let free_memory_pointer_detector = FreeMemoryPointerDetector::new(self.bytecode.clone());
        let free_memory_pointer_vulnerabilities = free_memory_pointer_detector.detect_vulnerabilities();
        total_vulnerabilities += free_memory_pointer_vulnerabilities.len() as u32;
        modules_run += 1;

        let friend_tech_curve_detector = FriendTechCurveDetector::new(self.bytecode.clone());
        let friend_tech_curve_vulnerabilities = friend_tech_curve_detector.detect_vulnerabilities();
        total_vulnerabilities += friend_tech_curve_vulnerabilities.len() as u32;
        modules_run += 1;

        let function_selector_collision_detector = FunctionSelectorCollisionDetector::new(self.bytecode.clone());
        let function_selector_collision_vulnerabilities = function_selector_collision_detector.detect_vulnerabilities();
        total_vulnerabilities += function_selector_collision_vulnerabilities.len() as u32;
        modules_run += 1;

        let function_shadowing_detector = FunctionShadowingDetector::new(self.bytecode.clone());
        let function_shadowing_vulnerabilities = function_shadowing_detector.detect_vulnerabilities();
        total_vulnerabilities += function_shadowing_vulnerabilities.len() as u32;
        modules_run += 1;

        let funding_rate_sniping_detector = FundingRateSnipingDetector::new(self.bytecode.clone());
        let funding_rate_sniping_vulnerabilities = funding_rate_sniping_detector.detect_vulnerabilities();
        total_vulnerabilities += funding_rate_sniping_vulnerabilities.len() as u32;
        modules_run += 1;

        let futarchy_market_detector = FutarchyMarketDetector::new(self.bytecode.clone());
        let futarchy_market_vulnerabilities = futarchy_market_detector.detect_vulnerabilities();
        total_vulnerabilities += futarchy_market_vulnerabilities.len() as u32;
        modules_run += 1;

        let future_timestamp_prediction_detector = FutureTimestampPredictionDetector::new(self.bytecode.clone());
        let future_timestamp_prediction_vulnerabilities = future_timestamp_prediction_detector.detect_vulnerabilities();
        total_vulnerabilities += future_timestamp_prediction_vulnerabilities.len() as u32;
        modules_run += 1;

        let futures_settlement_detector = FuturesSettlementDetector::new(self.bytecode.clone());
        let futures_settlement_vulnerabilities = futures_settlement_detector.detect_vulnerabilities();
        total_vulnerabilities += futures_settlement_vulnerabilities.len() as u32;
        modules_run += 1;

        let gas_limit_dependent_logic_detector = GasLimitDependentLogicDetector::new(self.bytecode.clone());
        let gas_limit_dependent_logic_vulnerabilities = gas_limit_dependent_logic_detector.detect_vulnerabilities();
        total_vulnerabilities += gas_limit_dependent_logic_vulnerabilities.len() as u32;
        modules_run += 1;

        let gas_refund_gaming_detector = GasRefundGamingDetector::new(self.bytecode.clone());
        let gas_refund_gaming_vulnerabilities = gas_refund_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += gas_refund_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let gas_sponsorship_detector = GasSponsorshipDetector::new(self.bytecode.clone());
        let gas_sponsorship_vulnerabilities = gas_sponsorship_detector.detect_vulnerabilities();
        total_vulnerabilities += gas_sponsorship_vulnerabilities.len() as u32;
        modules_run += 1;

        let gas_token_arbitrage_detector = GasTokenArbitrageDetector::new(self.bytecode.clone());
        let gas_token_arbitrage_vulnerabilities = gas_token_arbitrage_detector.detect_vulnerabilities();
        total_vulnerabilities += gas_token_arbitrage_vulnerabilities.len() as u32;
        modules_run += 1;

        let gearbox_credit_account_detector = GearboxCreditAccountDetector::new(self.bytecode.clone());
        let gearbox_credit_account_vulnerabilities = gearbox_credit_account_detector.detect_vulnerabilities();
        total_vulnerabilities += gearbox_credit_account_vulnerabilities.len() as u32;
        modules_run += 1;

        let geospatial_attack_detector = GeospatialAttackDetector::new(self.bytecode.clone());
        let geospatial_attack_vulnerabilities = geospatial_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += geospatial_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let gmx_v2_detector = GMXV2Detector::new(self.bytecode.clone());
        let gmx_v2_vulnerabilities = gmx_v2_detector.detect_vulnerabilities();
        total_vulnerabilities += gmx_v2_vulnerabilities.len() as u32;
        modules_run += 1;

        let gmx_v2_funding_rate_manipulation_detector = GmxV2FundingRateManipulationDetector::new(self.bytecode.clone());
        let gmx_v2_funding_rate_manipulation_vulnerabilities = gmx_v2_funding_rate_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += gmx_v2_funding_rate_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let gmx_v2_oracle_reader_inconsistency_detector = GmxV2OracleDetector::new(self.bytecode.clone());
        let gmx_v2_oracle_reader_inconsistency_vulnerabilities = gmx_v2_oracle_reader_inconsistency_detector.detect_vulnerabilities();
        total_vulnerabilities += gmx_v2_oracle_reader_inconsistency_vulnerabilities.len() as u32;
        modules_run += 1;

        let gnosis_safe_threshold_manipulation_detector = GnosisSafeThresholdManipulationDetector::new(self.bytecode.clone());
        let gnosis_safe_threshold_manipulation_vulnerabilities = gnosis_safe_threshold_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += gnosis_safe_threshold_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let governance_delegation_advanced_detector = GovernanceDelegationAdvancedDetector::new(self.bytecode.clone());
        let governance_delegation_advanced_vulnerabilities = governance_delegation_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += governance_delegation_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let governor_bravo_detector = GovernorBravoDetector::new(self.bytecode.clone());
        let governor_bravo_vulnerabilities = governor_bravo_detector.detect_vulnerabilities();
        total_vulnerabilities += governor_bravo_vulnerabilities.len() as u32;
        modules_run += 1;

        let governor_bravo_threshold_detector = GovernorBravoThresholdDetector::new(self.bytecode.clone());
        let governor_bravo_threshold_vulnerabilities = governor_bravo_threshold_detector.detect_vulnerabilities();
        total_vulnerabilities += governor_bravo_threshold_vulnerabilities.len() as u32;
        modules_run += 1;

        let grace_period_exploitation_detector = GracePeriodExploitationDetector::new(self.bytecode.clone());
        let grace_period_exploitation_vulnerabilities = grace_period_exploitation_detector.detect_vulnerabilities();
        total_vulnerabilities += grace_period_exploitation_vulnerabilities.len() as u32;
        modules_run += 1;

        let greeks_calculation_error_detector = GreeksCalculationErrorDetector::new(self.bytecode.clone());
        let greeks_calculation_error_vulnerabilities = greeks_calculation_error_detector.detect_vulnerabilities();
        total_vulnerabilities += greeks_calculation_error_vulnerabilities.len() as u32;
        modules_run += 1;

        let groth16_verification_key_reuse_detector = Groth16VerificationKeyReuseDetector::new(self.bytecode.clone());
        let groth16_verification_key_reuse_vulnerabilities = groth16_verification_key_reuse_detector.detect_vulnerabilities();
        total_vulnerabilities += groth16_verification_key_reuse_vulnerabilities.len() as u32;
        modules_run += 1;

        let gyroscope_eclp_manipulation_detector = GyroscopeEclpManipulationDetector::new(self.bytecode.clone());
        let gyroscope_eclp_manipulation_vulnerabilities = gyroscope_eclp_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += gyroscope_eclp_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let hardcoded_value_detector = HardcodedValueDetector::new(self.bytecode.clone());
        let hardcoded_value_vulnerabilities = hardcoded_value_detector.detect_vulnerabilities();
        total_vulnerabilities += hardcoded_value_vulnerabilities.len() as u32;
        modules_run += 1;

        let hardware_supply_chain_detector = HardwareSupplyChainDetector::new(self.bytecode.clone());
        let hardware_supply_chain_vulnerabilities = hardware_supply_chain_detector.detect_vulnerabilities();
        total_vulnerabilities += hardware_supply_chain_vulnerabilities.len() as u32;
        modules_run += 1;

        let hardware_wallet_exploit_detector = HardwareWalletExploitDetector::new(self.bytecode.clone());
        let hardware_wallet_exploit_vulnerabilities = hardware_wallet_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += hardware_wallet_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let historical_oracle_gaming_detector = HistoricalOracleGamingDetector::new(self.bytecode.clone());
        let historical_oracle_gaming_vulnerabilities = historical_oracle_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += historical_oracle_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let holographic_consensus_gaming_detector = HolographicConsensusGamingDetector::new(self.bytecode.clone());
        let holographic_consensus_gaming_vulnerabilities = holographic_consensus_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += holographic_consensus_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let homomorphic_encryption_misuse_detector = HomomorphicEncryptionMisuseDetector::new(self.bytecode.clone());
        let homomorphic_encryption_misuse_vulnerabilities = homomorphic_encryption_misuse_detector.detect_vulnerabilities();
        total_vulnerabilities += homomorphic_encryption_misuse_vulnerabilities.len() as u32;
        modules_run += 1;

        let honeypot_comprehensive_detector = HoneypotComprehensiveDetector::new(self.bytecode.clone());
        let honeypot_comprehensive_vulnerabilities = honeypot_comprehensive_detector.detect_vulnerabilities();
        total_vulnerabilities += honeypot_comprehensive_vulnerabilities.len() as u32;
        modules_run += 1;

        let hybrid_curve_detector = HybridCurveDetector::new(self.bytecode.clone());
        let hybrid_curve_vulnerabilities = hybrid_curve_detector.detect_vulnerabilities();
        total_vulnerabilities += hybrid_curve_vulnerabilities.len() as u32;
        modules_run += 1;

        let hybrid_exchange_detector = HybridExchangeDetector::new(self.bytecode.clone());
        let hybrid_exchange_vulnerabilities = hybrid_exchange_detector.detect_vulnerabilities();
        total_vulnerabilities += hybrid_exchange_vulnerabilities.len() as u32;
        modules_run += 1;

        let hyperbolic_discounting_exploit_detector = HyperbolicDiscountingExploitDetector::new(self.bytecode.clone());
        let hyperbolic_discounting_exploit_vulnerabilities = hyperbolic_discounting_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += hyperbolic_discounting_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let hyperlane_ism_detector = HyperlaneISMDetector::new(self.bytecode.clone());
        let hyperlane_ism_vulnerabilities = hyperlane_ism_detector.detect_vulnerabilities();
        total_vulnerabilities += hyperlane_ism_vulnerabilities.len() as u32;
        modules_run += 1;

        let immutable_initialization_detector = ImmutableInitializationDetector::new(self.bytecode.clone());
        let immutable_initialization_vulnerabilities = immutable_initialization_detector.detect_vulnerabilities();
        total_vulnerabilities += immutable_initialization_vulnerabilities.len() as u32;
        modules_run += 1;

        let immutable_shadow_detector = ImmutableShadowDetector::new(self.bytecode.clone());
        let immutable_shadow_vulnerabilities = immutable_shadow_detector.detect_vulnerabilities();
        total_vulnerabilities += immutable_shadow_vulnerabilities.len() as u32;
        modules_run += 1;

        let immutable_variable_detector = ImmutableVariableDetector::new(self.bytecode.clone());
        let immutable_variable_vulnerabilities = immutable_variable_detector.detect_vulnerabilities();
        total_vulnerabilities += immutable_variable_vulnerabilities.len() as u32;
        modules_run += 1;

        let impermanent_loss_attack_detector = ImpermanentLossAttackDetector::new(self.bytecode.clone());
        let impermanent_loss_attack_vulnerabilities = impermanent_loss_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += impermanent_loss_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let impermanent_loss_cascade_detector = ImpermanentLossCascadeDetector::new(self.bytecode.clone());
        let impermanent_loss_cascade_vulnerabilities = impermanent_loss_cascade_detector.detect_vulnerabilities();
        total_vulnerabilities += impermanent_loss_cascade_vulnerabilities.len() as u32;
        modules_run += 1;

        let impermanent_loss_exploit_detector = ImpermanentLossExploitDetector::new(self.bytecode.clone());
        let impermanent_loss_exploit_vulnerabilities = impermanent_loss_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += impermanent_loss_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let implied_volatility_solving_detector = ImpliedVolatilitySolvingDetector::new(self.bytecode.clone());
        let implied_volatility_solving_vulnerabilities = implied_volatility_solving_detector.detect_vulnerabilities();
        total_vulnerabilities += implied_volatility_solving_vulnerabilities.len() as u32;
        modules_run += 1;

        let incorrect_decimal_handling_detector = IncorrectDecimalHandlingDetector::new(self.bytecode.clone());
        let incorrect_decimal_handling_vulnerabilities = incorrect_decimal_handling_detector.detect_vulnerabilities();
        total_vulnerabilities += incorrect_decimal_handling_vulnerabilities.len() as u32;
        modules_run += 1;

        let indexer_subgraph_manipulation_detector = IndexerSubgraphManipulationDetector::new(self.bytecode.clone());
        let indexer_subgraph_manipulation_vulnerabilities = indexer_subgraph_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += indexer_subgraph_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let information_leakage_timing_detector = InformationLeakageTimingDetector::new(self.bytecode.clone());
        let information_leakage_timing_vulnerabilities = information_leakage_timing_detector.detect_vulnerabilities();
        total_vulnerabilities += information_leakage_timing_vulnerabilities.len() as u32;
        modules_run += 1;

        let initialization_race_condition_detector = InitializationRaceConditionDetector::new(self.bytecode.clone());
        let initialization_race_condition_vulnerabilities = initialization_race_condition_detector.detect_vulnerabilities();
        total_vulnerabilities += initialization_race_condition_vulnerabilities.len() as u32;
        modules_run += 1;

        let initialization_vulnerability_detector = InitializationVulnerabilityDetector::new(self.bytecode.clone());
        let initialization_vulnerability_vulnerabilities = initialization_vulnerability_detector.detect_vulnerabilities();
        total_vulnerabilities += initialization_vulnerability_vulnerabilities.len() as u32;
        modules_run += 1;

        let initializer_frontrun_detector = InitializerFrontrunDetector::new(self.bytecode.clone());
        let initializer_frontrun_vulnerabilities = initializer_frontrun_detector.detect_vulnerabilities();
        total_vulnerabilities += initializer_frontrun_vulnerabilities.len() as u32;
        modules_run += 1;

        let inline_assembly_memory_safe_annotation_detector = InlineAssemblyMemorySafeAnnotationDetector::new(self.bytecode.clone());
        let inline_assembly_memory_safe_annotation_vulnerabilities = inline_assembly_memory_safe_annotation_detector.detect_vulnerabilities();
        total_vulnerabilities += inline_assembly_memory_safe_annotation_vulnerabilities.len() as u32;
        modules_run += 1;

        let insurance_fund_socialized_loss_detector = InsuranceFundSocializedLossDetector::new(self.bytecode.clone());
        let insurance_fund_socialized_loss_vulnerabilities = insurance_fund_socialized_loss_detector.detect_vulnerabilities();
        total_vulnerabilities += insurance_fund_socialized_loss_vulnerabilities.len() as u32;
        modules_run += 1;

        let integer_safety_detector = IntegerSafetyDetector::new(self.bytecode.clone());
        let integer_safety_vulnerabilities = integer_safety_detector.detect_vulnerabilities();
        total_vulnerabilities += integer_safety_vulnerabilities.len() as u32;
        modules_run += 1;

        let intent_dutch_auction_detector = IntentDutchAuctionDetector::new(self.bytecode.clone());
        let intent_dutch_auction_vulnerabilities = intent_dutch_auction_detector.detect_vulnerabilities();
        total_vulnerabilities += intent_dutch_auction_vulnerabilities.len() as u32;
        modules_run += 1;

        let intent_manipulation_advanced_detector = IntentManipulationAdvancedDetector::new(self.bytecode.clone());
        let intent_manipulation_advanced_vulnerabilities = intent_manipulation_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += intent_manipulation_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let intent_orderflow_auction_detector = IntentOrderflowAuctionDetector::new(self.bytecode.clone());
        let intent_orderflow_auction_vulnerabilities = intent_orderflow_auction_detector.detect_vulnerabilities();
        total_vulnerabilities += intent_orderflow_auction_vulnerabilities.len() as u32;
        modules_run += 1;

        let intent_settlement_timing_detector = IntentSettlementTimingDetector::new(self.bytecode.clone());
        let intent_settlement_timing_vulnerabilities = intent_settlement_timing_detector.detect_vulnerabilities();
        total_vulnerabilities += intent_settlement_timing_vulnerabilities.len() as u32;
        modules_run += 1;

        let intent_solver_collusion_detector = IntentSolverCollusionDetector::new(self.bytecode.clone());
        let intent_solver_collusion_vulnerabilities = intent_solver_collusion_detector.detect_vulnerabilities();
        total_vulnerabilities += intent_solver_collusion_vulnerabilities.len() as u32;
        modules_run += 1;

        let inter_chain_messaging_delay_detector = InterChainMessagingDelayDetector::new(self.bytecode.clone());
        let inter_chain_messaging_delay_vulnerabilities = inter_chain_messaging_delay_detector.detect_vulnerabilities();
        total_vulnerabilities += inter_chain_messaging_delay_vulnerabilities.len() as u32;
        modules_run += 1;

        let interest_rate_model_exploit_detector = InterestRateModelExploitDetector::new(self.bytecode.clone());
        let interest_rate_model_exploit_vulnerabilities = interest_rate_model_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += interest_rate_model_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let interface_confusion_detector = InterfaceConfusionDetector::new(self.bytecode.clone());
        let interface_confusion_vulnerabilities = interface_confusion_detector.detect_vulnerabilities();
        total_vulnerabilities += interface_confusion_vulnerabilities.len() as u32;
        modules_run += 1;

        let internal_function_visibility_detector = InternalFunctionVisibilityDetector::new(self.bytecode.clone());
        let internal_function_visibility_vulnerabilities = internal_function_visibility_detector.detect_vulnerabilities();
        total_vulnerabilities += internal_function_visibility_vulnerabilities.len() as u32;
        modules_run += 1;

        let intra_block_state_accumulation_detector = IntraBlockStateAccumulationDetector::new(self.bytecode.clone());
        let intra_block_state_accumulation_vulnerabilities = intra_block_state_accumulation_detector.detect_vulnerabilities();
        total_vulnerabilities += intra_block_state_accumulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let invalid_jumpdest_detector = InvalidJumpdestDetector::new(self.bytecode.clone());
        let invalid_jumpdest_vulnerabilities = invalid_jumpdest_detector.detect_vulnerabilities();
        total_vulnerabilities += invalid_jumpdest_vulnerabilities.len() as u32;
        modules_run += 1;

        let iot_oracle_manipulation_detector = IoTOracleManipulationDetector::new(self.bytecode.clone());
        let iot_oracle_manipulation_vulnerabilities = iot_oracle_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += iot_oracle_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let isolated_market_manipulation_detector = IsolatedMarketManipulationDetector::new(self.bytecode.clone());
        let isolated_market_manipulation_vulnerabilities = isolated_market_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += isolated_market_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let jit_liquidity_sandwich_detector = JitLiquiditySandwichDetector::new(self.bytecode.clone());
        let jit_liquidity_sandwich_vulnerabilities = jit_liquidity_sandwich_detector.detect_vulnerabilities();
        total_vulnerabilities += jit_liquidity_sandwich_vulnerabilities.len() as u32;
        modules_run += 1;

        let just_in_time_liquidity_detector = JustInTimeLiquidityDetector::new(self.bytecode.clone());
        let just_in_time_liquidity_vulnerabilities = just_in_time_liquidity_detector.detect_vulnerabilities();
        total_vulnerabilities += just_in_time_liquidity_vulnerabilities.len() as u32;
        modules_run += 1;

        let just_in_time_lp_detector = JustInTimeLpDetector::new(self.bytecode.clone());
        let just_in_time_lp_vulnerabilities = just_in_time_lp_detector.detect_vulnerabilities();
        total_vulnerabilities += just_in_time_lp_vulnerabilities.len() as u32;
        modules_run += 1;

        let k_anonymity_violation_detector = KAnonymityViolationDetector::new(self.bytecode.clone());
        let k_anonymity_violation_vulnerabilities = k_anonymity_violation_detector.detect_vulnerabilities();
        total_vulnerabilities += k_anonymity_violation_vulnerabilities.len() as u32;
        modules_run += 1;

        let karak_dss_restaking_detector = KarakDssRestakingDetector::new(self.bytecode.clone());
        let karak_dss_restaking_vulnerabilities = karak_dss_restaking_detector.detect_vulnerabilities();
        total_vulnerabilities += karak_dss_restaking_vulnerabilities.len() as u32;
        modules_run += 1;

        let keeper_networks_detector = KeeperNetworksDetector::new(self.bytecode.clone());
        let keeper_networks_vulnerabilities = keeper_networks_detector.detect_vulnerabilities();
        total_vulnerabilities += keeper_networks_vulnerabilities.len() as u32;
        modules_run += 1;

        let kernel_account_detector = KernelAccountDetector::new(self.bytecode.clone());
        let kernel_account_vulnerabilities = kernel_account_detector.detect_vulnerabilities();
        total_vulnerabilities += kernel_account_vulnerabilities.len() as u32;
        modules_run += 1;

        let kyberswap_elastic_tick_manipulation_detector = KyberSwapElasticTickManipulationDetector::new(self.bytecode.clone());
        let kyberswap_elastic_tick_manipulation_vulnerabilities = kyberswap_elastic_tick_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += kyberswap_elastic_tick_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let kyc_revocation_fund_lock_detector = KycRevocationFundLockDetector::new(self.bytecode.clone());
        let kyc_revocation_fund_lock_vulnerabilities = kyc_revocation_fund_lock_detector.detect_vulnerabilities();
        total_vulnerabilities += kyc_revocation_fund_lock_vulnerabilities.len() as u32;
        modules_run += 1;

        let kzg_commitment_attack_detector = KzgCommitmentAttackDetector::new(self.bytecode.clone());
        let kzg_commitment_attack_vulnerabilities = kzg_commitment_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += kzg_commitment_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let l2_fee_market_manipulation_detector = L2FeeMarketManipulationDetector::new(self.bytecode.clone());
        let l2_fee_market_manipulation_vulnerabilities = l2_fee_market_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += l2_fee_market_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let l2_gas_estimation_vs_actual_gap_detector = L2GasEstimationVsActualGapDetector::new(self.bytecode.clone());
        let l2_gas_estimation_vs_actual_gap_vulnerabilities = l2_gas_estimation_vs_actual_gap_detector.detect_vulnerabilities();
        total_vulnerabilities += l2_gas_estimation_vs_actual_gap_vulnerabilities.len() as u32;
        modules_run += 1;

        let l2_reorg_attack_detector = L2ReorgAttackDetector::new(self.bytecode.clone());
        let l2_reorg_attack_vulnerabilities = l2_reorg_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += l2_reorg_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let l2_state_compression_exploit_detector = L2StateCompressionExploitDetector::new(self.bytecode.clone());
        let l2_state_compression_exploit_vulnerabilities = l2_state_compression_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += l2_state_compression_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let l2_timestamp_dependency_detector = L2TimestampDependencyDetector::new(self.bytecode.clone());
        let l2_timestamp_dependency_vulnerabilities = l2_timestamp_dependency_detector.detect_vulnerabilities();
        total_vulnerabilities += l2_timestamp_dependency_vulnerabilities.len() as u32;
        modules_run += 1;

        let late_quorum_extension_griefing_detector = LateQuorumExtensionGriefingDetector::new(self.bytecode.clone());
        let late_quorum_extension_griefing_vulnerabilities = late_quorum_extension_griefing_detector.detect_vulnerabilities();
        total_vulnerabilities += late_quorum_extension_griefing_vulnerabilities.len() as u32;
        modules_run += 1;

        let layerzero_oft_detector = LayerZeroOftDetector::new(self.bytecode.clone());
        let layerzero_oft_vulnerabilities = layerzero_oft_detector.detect_vulnerabilities();
        total_vulnerabilities += layerzero_oft_vulnerabilities.len() as u32;
        modules_run += 1;

        let layerzero_relayer_centralization_detector = LayerzeroRelayerCentralizationDetector::new(self.bytecode.clone());
        let layerzero_relayer_centralization_vulnerabilities = layerzero_relayer_centralization_detector.detect_vulnerabilities();
        total_vulnerabilities += layerzero_relayer_centralization_vulnerabilities.len() as u32;
        modules_run += 1;

        let lbp_manipulation_detector = LBPManipulationDetector::new(self.bytecode.clone());
        let lbp_manipulation_vulnerabilities = lbp_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += lbp_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let lending_utilization_rate_detector = LendingUtilizationRateDetector::new(self.bytecode.clone());
        let lending_utilization_rate_vulnerabilities = lending_utilization_rate_detector.detect_vulnerabilities();
        total_vulnerabilities += lending_utilization_rate_vulnerabilities.len() as u32;
        modules_run += 1;

        let level_finance_twap_detector = LevelFinanceTwapDetector::new(self.bytecode.clone());
        let level_finance_twap_vulnerabilities = level_finance_twap_detector.detect_vulnerabilities();
        total_vulnerabilities += level_finance_twap_vulnerabilities.len() as u32;
        modules_run += 1;

        let library_delegatecall_detector = LibraryDelegatecallDetector::new(self.bytecode.clone());
        let library_delegatecall_vulnerabilities = library_delegatecall_detector.detect_vulnerabilities();
        total_vulnerabilities += library_delegatecall_vulnerabilities.len() as u32;
        modules_run += 1;

        let lido_steth_share_rounding_detector = LidoStethShareRoundingDetector::new(self.bytecode.clone());
        let lido_steth_share_rounding_vulnerabilities = lido_steth_share_rounding_detector.detect_vulnerabilities();
        total_vulnerabilities += lido_steth_share_rounding_vulnerabilities.len() as u32;
        modules_run += 1;

        let light_account_detector = LightAccountDetector::new(self.bytecode.clone());
        let light_account_vulnerabilities = light_account_detector.detect_vulnerabilities();
        total_vulnerabilities += light_account_vulnerabilities.len() as u32;
        modules_run += 1;

        let light_client_header_forgery_detector = LightClientHeaderForgeryDetector::new(self.bytecode.clone());
        let light_client_header_forgery_vulnerabilities = light_client_header_forgery_detector.detect_vulnerabilities();
        total_vulnerabilities += light_client_header_forgery_vulnerabilities.len() as u32;
        modules_run += 1;

        let limit_order_exploit_detector = LimitOrderExploitDetector::new(self.bytecode.clone());
        let limit_order_exploit_vulnerabilities = limit_order_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += limit_order_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let linea_bridge_detector = LineaBridgeDetector::new(self.bytecode.clone());
        let linea_bridge_vulnerabilities = linea_bridge_detector.detect_vulnerabilities();
        total_vulnerabilities += linea_bridge_vulnerabilities.len() as u32;
        modules_run += 1;

        let linea_canonical_message_service_detector = LineaCanonicalMessageServiceDetector::new(self.bytecode.clone());
        let linea_canonical_message_service_vulnerabilities = linea_canonical_message_service_detector.detect_vulnerabilities();
        total_vulnerabilities += linea_canonical_message_service_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquid_democracy_proxy_chain_detector = LiquidDemocracyProxyChainDetector::new(self.bytecode.clone());
        let liquid_democracy_proxy_chain_vulnerabilities = liquid_democracy_proxy_chain_detector.detect_vulnerabilities();
        total_vulnerabilities += liquid_democracy_proxy_chain_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquid_staking_depeg_cascade_liquidation_detector = LiquidStakingDepegCascadeLiquidationDetector::new(self.bytecode.clone());
        let liquid_staking_depeg_cascade_liquidation_vulnerabilities = liquid_staking_depeg_cascade_liquidation_detector.detect_vulnerabilities();
        total_vulnerabilities += liquid_staking_depeg_cascade_liquidation_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidation_cascade_detector = LiquidationCascadeDetector::new(self.bytecode.clone());
        let liquidation_cascade_vulnerabilities = liquidation_cascade_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidation_cascade_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidation_threshold_gaming_detector = LiquidationThresholdGamingDetector::new(self.bytecode.clone());
        let liquidation_threshold_gaming_vulnerabilities = liquidation_threshold_gaming_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidation_threshold_gaming_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_book_bin_detector = LiquidityBookBinDetector::new(self.bytecode.clone());
        let liquidity_book_bin_vulnerabilities = liquidity_book_bin_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_book_bin_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_crunch_timing_detector = LiquidityCrunchTimingDetector::new(self.bytecode.clone());
        let liquidity_crunch_timing_vulnerabilities = liquidity_crunch_timing_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_crunch_timing_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_fragmentation_detector = LiquidityFragmentationDetector::new(self.bytecode.clone());
        let liquidity_fragmentation_vulnerabilities = liquidity_fragmentation_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_fragmentation_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_lock_bypass_detector = LiquidityLockBypassDetector::new(self.bytecode.clone());
        let liquidity_lock_bypass_vulnerabilities = liquidity_lock_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_lock_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_mining_exploit_detector = LiquidityMiningExploitDetector::new(self.bytecode.clone());
        let liquidity_mining_exploit_vulnerabilities = liquidity_mining_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_mining_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let liquidity_removal_race_detector = LiquidityRemovalRaceDetector::new(self.bytecode.clone());
        let liquidity_removal_race_vulnerabilities = liquidity_removal_race_detector.detect_vulnerabilities();
        total_vulnerabilities += liquidity_removal_race_vulnerabilities.len() as u32;
        modules_run += 1;

        let locked_ether_detector = LockedEtherDetector::new(self.bytecode.clone());
        let locked_ether_vulnerabilities = locked_ether_detector.detect_vulnerabilities();
        total_vulnerabilities += locked_ether_vulnerabilities.len() as u32;
        modules_run += 1;

        let log_data_manipulation_detector = LogDataManipulationDetector::new(self.bytecode.clone());
        let log_data_manipulation_vulnerabilities = log_data_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += log_data_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let logarithm_approximation_attack_detector = LogarithmApproximationAttackDetector::new(self.bytecode.clone());
        let logarithm_approximation_attack_vulnerabilities = logarithm_approximation_attack_detector.detect_vulnerabilities();
        total_vulnerabilities += logarithm_approximation_attack_vulnerabilities.len() as u32;
        modules_run += 1;

        let maker_endgame_detector = MakerEndgameDetector::new(self.bytecode.clone());
        let maker_endgame_vulnerabilities = maker_endgame_detector.detect_vulnerabilities();
        total_vulnerabilities += maker_endgame_vulnerabilities.len() as u32;
        modules_run += 1;

        let maker_psm_arbitrage_detector = MakerPsmArbitrageDetector::new(self.bytecode.clone());
        let maker_psm_arbitrage_vulnerabilities = maker_psm_arbitrage_detector.detect_vulnerabilities();
        total_vulnerabilities += maker_psm_arbitrage_vulnerabilities.len() as u32;
        modules_run += 1;

        let makerdao_gsm_bypass_detector = MakerdaoGsmBypassDetector::new(self.bytecode.clone());
        let makerdao_gsm_bypass_vulnerabilities = makerdao_gsm_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += makerdao_gsm_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let mango_oracle_manipulation_detector = MangoOracleManipulationDetector::new(self.bytecode.clone());
        let mango_oracle_manipulation_vulnerabilities = mango_oracle_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += mango_oracle_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let mantle_bridge_detector = MantleBridgeDetector::new(self.bytecode.clone());
        let mantle_bridge_vulnerabilities = mantle_bridge_detector.detect_vulnerabilities();
        total_vulnerabilities += mantle_bridge_vulnerabilities.len() as u32;
        modules_run += 1;

        let mark_index_price_deviation_detector = MarkIndexPriceDeviationDetector::new(self.bytecode.clone());
        let mark_index_price_deviation_vulnerabilities = mark_index_price_deviation_detector.detect_vulnerabilities();
        total_vulnerabilities += mark_index_price_deviation_vulnerabilities.len() as u32;
        modules_run += 1;

        let mark_price_manipulation_detector = MarkPriceManipulationDetector::new(self.bytecode.clone());
        let mark_price_manipulation_vulnerabilities = mark_price_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += mark_price_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let matrix_operation_exploit_detector = MatrixOperationExploitDetector::new(self.bytecode.clone());
        let matrix_operation_exploit_vulnerabilities = matrix_operation_exploit_detector.detect_vulnerabilities();
        total_vulnerabilities += matrix_operation_exploit_vulnerabilities.len() as u32;
        modules_run += 1;

        let maturity_date_manipulation_detector = MaturityDateManipulationDetector::new(self.bytecode.clone());
        let maturity_date_manipulation_vulnerabilities = maturity_date_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += maturity_date_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let maverick_mode_switching_detector = MaverickModeSwitchingDetector::new(self.bytecode.clone());
        let maverick_mode_switching_vulnerabilities = maverick_mode_switching_detector.detect_vulnerabilities();
        total_vulnerabilities += maverick_mode_switching_vulnerabilities.len() as u32;
        modules_run += 1;

        let max_transaction_bypass_detector = MaxTransactionBypassDetector::new(self.bytecode.clone());
        let max_transaction_bypass_vulnerabilities = max_transaction_bypass_detector.detect_vulnerabilities();
        total_vulnerabilities += max_transaction_bypass_vulnerabilities.len() as u32;
        modules_run += 1;

        let mcopy_memory_corruption_detector = McopyMemoryCorruptionDetector::new(self.bytecode.clone());
        let mcopy_memory_corruption_vulnerabilities = mcopy_memory_corruption_detector.detect_vulnerabilities();
        total_vulnerabilities += mcopy_memory_corruption_vulnerabilities.len() as u32;
        modules_run += 1;

        let mechanism_design_failure_detector = MechanismDesignFailureDetector::new(self.bytecode.clone());
        let mechanism_design_failure_vulnerabilities = mechanism_design_failure_detector.detect_vulnerabilities();
        total_vulnerabilities += mechanism_design_failure_vulnerabilities.len() as u32;
        modules_run += 1;

        let median_oracle_manipulation_detector = MedianOracleManipulationDetector::new(self.bytecode.clone());
        let median_oracle_manipulation_vulnerabilities = median_oracle_manipulation_detector.detect_vulnerabilities();
        total_vulnerabilities += median_oracle_manipulation_vulnerabilities.len() as u32;
        modules_run += 1;

        let mellow_lrt_vault_arbitrage_detector = MellowLrtVaultArbitrageDetector::new(self.bytecode.clone());
        let mellow_lrt_vault_arbitrage_vulnerabilities = mellow_lrt_vault_arbitrage_detector.detect_vulnerabilities();
        total_vulnerabilities += mellow_lrt_vault_arbitrage_vulnerabilities.len() as u32;
        modules_run += 1;

        let memory_expansion_dos_detector = MemoryExpansionDoSDetector::new(self.bytecode.clone());
        let memory_expansion_dos_vulnerabilities = memory_expansion_dos_detector.detect_vulnerabilities();
        total_vulnerabilities += memory_expansion_dos_vulnerabilities.len() as u32;
        modules_run += 1;

        let mempool_sniping_advanced_detector = MempoolSnipingAdvancedDetector::new(self.bytecode.clone());
        let mempool_sniping_advanced_vulnerabilities = mempool_sniping_advanced_detector.detect_vulnerabilities();
        total_vulnerabilities += mempool_sniping_advanced_vulnerabilities.len() as u32;
        modules_run += 1;

        let mercenary_capital_detector = MercenaryCapitalDetector::new(self.bytecode.clone());
        let mercenary_capital_vulnerabilities = mercenary_capital_detector.detect_vulnerabilities();
        total_vulnerabilities += mercenary_capital_vulnerabilities.len() as u32;
        modules_run += 1;

        let merkle_airdrop_detector = MerkleAirdropDetector::new(self.bytecode.clone());
        let merkle_airdrop_vulnerabilities = merkle_airdrop_detector.detect_vulnerabilities();
        total_vulnerabilities += merkle_airdrop_vulnerabilities.len() as u32;
        modules_run += 1;

        let merkle_proof_detector = MerkleProofDetector::new(self.bytecode.clone());
        let merkle_proof_vulnerabilities = merkle_proof_detector.detect_vulnerabilities();
        total_vulnerabilities += merkle_proof_vulnerabilities.len() as u32;
        modules_run += 1;

        let merkle_tree_second_preimage_detector = MerkleTreeSecondPreimageDetector::new(self.bytecode.clone());
        let merkle_tree_second_preimage_vulnerabilities = merkle_tree_second_preimage_detector.detect_vulnerabilities();
        total_vulnerabilities += merkle_tree_second_preimage_vulnerabilities.len() as u32;
        modules_run += 1;

        let message_delay_arbitrage_detector = MessageDelayArbitrageDetector::new(self.bytecode.clone());
        let message_delay_arbitrage_vulnerabilities = message_delay_arbitrage_detector.detect_vulnerabilities();
        total_vulnerabilities += message_delay_arbitrage_vulnerabilities.len() as u32;
        modules_run += 1;

        let metamorphic_contract_detector = MetamorphicContractDetector::new(self.bytecode.clone());
        let metamorphic_contract_vulnerabilities = metamorphic_contract_detector.detect_vulnerabilities();
        total_vulnerabilities += metamorphic_contract_vulnerabilities.len() as u32;
        modules_run += 1;

        let metcalfe_law_exploitation_detector = MetcalfeLawExploitationDetector::new(self.bytecode.clone());
        let metcalfe_law_exploitation_vulnerabilities = metcalfe_law_exploitation_detector.detect_vulnerabilities();
        total_vulnerabilities += metcalfe_law_exploitation_vulnerabilities.len() as u32;
        modules_run += 1;

        let metis_bridge_detector = MetisBridgeDetector::new(self.bytecode.clone());
        let metis_bridge_vulnerabilities = metis_bridge_detector.detect_vulnerabilities();
        total_vulnerabilities += metis_bridge_vulnerabilities.len() as u32;
        modules_run += 1;

        // MevAttackChainDetector requires EVMExecutionTrace, not bytecode - skip for static analysis
        // modules_run += 1; // Not counting this since we're skipping it

        let mev_protection_detector = MevProtectionDetector::new(self.bytecode.clone());
        let mev_protection_vulnerabilities = mev_protection_detector.detect_vulnerabilities();
        total_vulnerabilities += mev_protection_vulnerabilities.len() as u32;
        modules_run += 1;

        let mev_share_detector = MEVShareDetector::new(self.bytecode.clone());
        let mev_share_vulnerabilities = mev_share_detector.detect_vulnerabilities();
        total_vulnerabilities += mev_share_vulnerabilities.len() as u32;
        modules_run += 1;

        let mev_share_v2_detector = MEVShareV2Detector::new(self.bytecode.clone());
        let mev_share_v2_vulnerabilities = mev_share_v2_detector.detect_vulnerabilities();
        total_vulnerabilities += mev_share_v2_vulnerabilities.len() as u32;
        modules_run += 1;

        let mev_smoothing_exploitation_detector = MEVSmoothingExploitationDetector::new(self.bytecode.clone());
        let mev_smoothing_exploitation_vulnerabilities = mev_smoothing_exploitation_detector.detect_vulnerabilities();
        total_vulnerabilities += mev_smoothing_exploitation_vulnerabilities.len() as u32;
        modules_run += 1;

        let middleware_hook_reentrancy_detector = MiddlewareHookReentrancyDetector::new(self.bytecode.clone());
        let middleware_hook_reentrancy_vulnerabilities = middleware_hook_reentrancy_detector.detect_vulnerabilities();
        total_vulnerabilities += middleware_hook_reentrancy_vulnerabilities.len() as u32;
        modules_run += 1;

        let migration_frontrunning_detector = MigrationFrontrunningDetector::new(self.bytecode.clone());
        let migration_frontrunning_vulnerabilities = migration_frontrunning_detector.detect_vulnerabilities();
        total_vulnerabilities += migration_frontrunning_vulnerabilities.len() as u32;
        modules_run += 1;

        let time_weighted_function_detector = TimeWeightedFunctionDetector::new(self.bytecode.clone());
            let mut time_weighted_function_vulnerabilities = time_weighted_function_detector.detect_vulnerabilities();
            total_vulnerabilities += time_weighted_function_vulnerabilities.len() as u32;
            modules_run += 1;

            let aave_detector = AaveV3EModeDetector::new(self.bytecode.clone());
            let mut aave_emode_vulnerabilities = aave_detector.detect_vulnerabilities();
            total_vulnerabilities += aave_emode_vulnerabilities.len() as u32;
            modules_run += 1;

            let eip4844_detector = EIP4844BlobDetector::new(self.bytecode.clone());
            let mut eip4844_blob_vulnerabilities = eip4844_detector.detect_vulnerabilities();
            total_vulnerabilities += eip4844_blob_vulnerabilities.len() as u32;
            modules_run += 1;

            let returndatasize_detector = ReturndatasizeBombDetector::new(self.bytecode.clone());
            let mut returndatasize_vulnerabilities = returndatasize_detector.detect_vulnerabilities();
            total_vulnerabilities += returndatasize_vulnerabilities.len() as u32;
            modules_run += 1;

            let selector_detector = FunctionSelectorCollisionDetector::new(self.bytecode.clone());
            let mut function_selector_vulnerabilities = selector_detector.detect_vulnerabilities();
            total_vulnerabilities += function_selector_vulnerabilities.len() as u32;
            modules_run += 1;

            let fallback_detector = FallbackReceiveAmbiguityDetector::new(self.bytecode.clone());
            let mut fallback_receive_vulnerabilities = fallback_detector.detect_vulnerabilities();
            total_vulnerabilities += fallback_receive_vulnerabilities.len() as u32;
            modules_run += 1;

            let seneca_proxy_collision_detector = SenecaProxyCollisionDetector::new(self.bytecode.clone());
            let mut seneca_proxy_collision_vulnerabilities = seneca_proxy_collision_detector.detect_vulnerabilities();
            total_vulnerabilities += seneca_proxy_collision_vulnerabilities.len() as u32;
            modules_run += 1;

            let sense_term_structure_detector = SenseTermStructureDetector::new(self.bytecode.clone());
            let mut sense_term_structure_vulnerabilities = sense_term_structure_detector.detect_vulnerabilities();
            total_vulnerabilities += sense_term_structure_vulnerabilities.len() as u32;
            modules_run += 1;

            let sequencer_decentralization_progressive_detector = SequencerDecentralizationProgressiveDetector::new(self.bytecode.clone());
            let mut sequencer_decentralization_progressive_vulnerabilities = sequencer_decentralization_progressive_detector.detect_vulnerabilities();
            total_vulnerabilities += sequencer_decentralization_progressive_vulnerabilities.len() as u32;
            modules_run += 1;

            let multi_vault_interaction_detector = MultiVaultInteractionDetector::new(self.bytecode.clone());
            let mut multi_vault_interaction_vulnerabilities = multi_vault_interaction_detector.detect_vulnerabilities();
            total_vulnerabilities += multi_vault_interaction_vulnerabilities.len() as u32;
            modules_run += 1;

            let ponzi_economics_detector = PonziEconomicsDetector::new(self.bytecode.clone());
            let mut ponzi_economics_vulnerabilities = ponzi_economics_detector.detect_vulnerabilities();
            total_vulnerabilities += ponzi_economics_vulnerabilities.len() as u32;
            modules_run += 1;

            let private_transfer_detector = PrivateTransferDetector::new(self.bytecode.clone());
            let mut private_transfer_vulnerabilities = private_transfer_detector.detect_vulnerabilities();
            total_vulnerabilities += private_transfer_vulnerabilities.len() as u32;
            modules_run += 1;

        let proposer_builder_collusion_detector = ProposerBuilderCollusionDetector::new(self.bytecode.clone());
        let proposer_builder_collusion_vulnerabilities = proposer_builder_collusion_detector.detect_vulnerabilities();
        modules_run += 1;

        let protocol_hook_detector = ProtocolHookDetector::new(self.bytecode.clone());
        let protocol_hook_vulnerabilities = protocol_hook_detector.detect_vulnerabilities();
        modules_run += 1;

        let protocol_subsidy_gaming_detector = ProtocolSubsidyGamingDetector::new(self.bytecode.clone());
        let protocol_subsidy_gaming_vulnerabilities = protocol_subsidy_gaming_detector.detect_vulnerabilities();
        modules_run += 1;

        let selfish_mining_detector = SelfishMiningDetector::new(self.bytecode.clone());
        let selfish_mining_vulnerabilities = selfish_mining_detector.detect_vulnerabilities();
        modules_run += 1;

        let sequencer_censorship_detector = SequencerCensorshipDetector::new(self.bytecode.clone());
        let sequencer_censorship_vulnerabilities = sequencer_censorship_detector.detect_vulnerabilities();
        modules_run += 1;

        let settlement_layer_detector = SettlementLayerDetector::new(self.bytecode.clone());
        let settlement_layer_vulnerabilities = settlement_layer_detector.detect_vulnerabilities();
        modules_run += 1;

        let slot_auction_manipulation_detector = SlotAuctionManipulationDetector::new(self.bytecode.clone());
        let slot_auction_manipulation_vulnerabilities = slot_auction_manipulation_detector.detect_vulnerabilities();
        modules_run += 1;

        let sqrt_price_manipulation_detector = SqrtPriceManipulationDetector::new(self.bytecode.clone());
        let sqrt_price_manipulation_vulnerabilities = sqrt_price_manipulation_detector.detect_vulnerabilities();
        modules_run += 1;

        let stableswap_invariant_detector = StableswapInvariantDetector::new(self.bytecode.clone());
        let stableswap_invariant_vulnerabilities = stableswap_invariant_detector.detect_vulnerabilities();
        modules_run += 1;

        let state_root_fraud_detector = StateRootFraudDetector::new(self.bytecode.clone());
        let mut state_root_fraud_vulnerabilities = state_root_fraud_detector.detect_vulnerabilities();
        modules_run += 1;

        let storage_collision_detector = StorageCollisionDetector::new(self.bytecode.clone());
        let storage_collision_vulnerabilities = storage_collision_detector.detect_vulnerabilities();
        modules_run += 1;

        let tragedy_of_commons_detector = TragedyOfCommonsDetector::new(self.bytecode.clone());
        let tragedy_of_commons_vulnerabilities = tragedy_of_commons_detector.detect_vulnerabilities();
        modules_run += 1;

        let transaction_ordering_detector = TransactionOrderingDetector::new(self.bytecode.clone());
        let transaction_ordering_vulnerabilities = transaction_ordering_detector.detect_vulnerabilities();
        modules_run += 1;

        let uncle_bandit_detector = UncleBanditDetector::new(self.bytecode.clone());
        let uncle_bandit_vulnerabilities = uncle_bandit_detector.detect_vulnerabilities();
        modules_run += 1;

        let vampire_attack_detector = VampireAttackDetector::new(self.bytecode.clone());
        let vampire_attack_vulnerabilities = vampire_attack_detector.detect_vulnerabilities();
        modules_run += 1;

        let vault_share_inflation_detector = VaultShareInflationDetector::new(self.bytecode.clone());
        let mut vault_share_inflation_vulnerabilities = vault_share_inflation_detector.detect_vulnerabilities();
        modules_run += 1;

        let vault_strategy_migration_detector = VaultStrategyMigrationDetector::new(self.bytecode.clone());
        let vault_strategy_migration_vulnerabilities = vault_strategy_migration_detector.detect_vulnerabilities();
        modules_run += 1;

        let ve_tokenomics_detector = VeTokenomicsDetector::new(self.bytecode.clone());
        let ve_tokenomics_vulnerabilities = ve_tokenomics_detector.detect_vulnerabilities();
        modules_run += 1;

        let withdrawal_delay_detector = WithdrawalDelayDetector::new(self.bytecode.clone());
        let withdrawal_delay_vulnerabilities = withdrawal_delay_detector.detect_vulnerabilities();
        modules_run += 1;

        let yield_aggregator_detector = YieldAggregatorDetector::new(self.bytecode.clone());
        let yield_aggregator_vulnerabilities = yield_aggregator_detector.detect_vulnerabilities();
        modules_run += 1;

        // === ALL 161 DETECTORS NOW ADDED! ===

        // === NEW CRITICAL DETECTORS (56 INSTANTIATIONS) ===
        let vyper_compiler_reentrancy_vulnerabilities = VyperCompilerReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let donation_attack_advanced_vulnerabilities = DonationAttackAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let vault_deposit_manipulation_vulnerabilities = VaultDepositManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let concentrated_liquidity_tick_exploit_vulnerabilities = ConcentratedLiquidityTickExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bridge_key_compromise_vulnerabilities = BridgeKeyCompromiseDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let vyper_lock_mechanism_vulnerabilities = VyperLockMechanismDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let emergency_function_abuse_vulnerabilities = EmergencyFunctionAbuseDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let read_only_reentrancy_v2_vulnerabilities = ReadOnlyReentrancyV2Detector::new(self.bytecode.clone()).detect_vulnerabilities();
        let cross_protocol_mev_coordination_vulnerabilities = CrossProtocolMevCoordinationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let intent_manipulation_advanced_vulnerabilities = IntentManipulationAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc6900_module_security_vulnerabilities = Erc6900ModuleSecurityDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let eip7702_delegation_vulnerabilities = Eip7702DelegationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let blob_mev_extraction_vulnerabilities = BlobMevExtractionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let transient_storage_attack_vulnerabilities = TransientStorageAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let aave_v3_emode_liquidation_vulnerabilities = AaveV3EmodeLiquidationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let compound_v3_absorption_vulnerabilities = CompoundV3AbsorptionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let uniswap_v4_hook_griefing_advanced_vulnerabilities = UniswapV4HookGriefingAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let curve_vyper_pool_bug_vulnerabilities = CurveVyperPoolBugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let balancer_v3_precision_vulnerabilities = BalancerV3PrecisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let gmx_v2_funding_rate_manipulation_vulnerabilities = GmxV2FundingRateManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let pendle_v2_sy_token_vulnerabilities = PendleV2SyTokenDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let liquidity_fragmentation_vulnerabilities = LiquidityFragmentationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let impermanent_loss_cascade_vulnerabilities = ImpermanentLossCascadeDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let yield_harvest_sandwich_vulnerabilities = YieldHarvestSandwichDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let vault_share_dilution_advanced_vulnerabilities = VaultShareDilutionAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let options_mispricing_vulnerabilities = OptionsMispricingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let perp_funding_arbitrage_vulnerabilities = PerpFundingArbitrageDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let rebalance_timing_mev_vulnerabilities = RebalanceTimingMevDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let optimistic_finality_attack_vulnerabilities = OptimisticFinalityAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut zkevm_circuit_bug_vulnerabilities = ZkevmCircuitBugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let message_delay_arbitrage_vulnerabilities = MessageDelayArbitrageDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bridge_liquidity_drain_vulnerabilities = BridgeLiquidityDrainDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut sequencer_censorship_mev_advanced_vulnerabilities = SequencerCensorshipMevAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let da_sampling_vulnerability_vulnerabilities = DaSamplingVulnerabilityDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let proof_market_manipulation_vulnerabilities = ProofMarketManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut paymaster_dos_advanced_vulnerabilities = PaymasterDosAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bundler_censorship_vulnerabilities = BundlerCensorshipDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut signature_aggregation_exploit_vulnerabilities = SignatureAggregationExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut session_key_escalation_vulnerabilities = SessionKeyEscalationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc7579_module_conflict_vulnerabilities = Erc7579ModuleConflictDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut validation_gas_griefing_vulnerabilities = ValidationGasGriefingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut aa_nonce_management_vulnerabilities = AaNonceManagementDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut dynamic_nft_state_exploit_vulnerabilities = DynamicNftStateExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let nft_lending_oracle_vulnerabilities = NftLendingOracleDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let nft_rental_griefing_vulnerabilities = NftRentalGriefingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut soulbound_transfer_bypass_vulnerabilities = SoulboundTransferBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let gaming_rng_prediction_vulnerabilities = GamingRngPredictionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut achievement_exploit_vulnerabilities = AchievementExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let lootbox_fairness_vulnerabilities = LootboxFairnessDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bls_aggregation_vulnerability_vulnerabilities = BlsAggregationVulnerabilityDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut verkle_proof_manipulation_vulnerabilities = VerkleProofManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let kzg_commitment_attack_vulnerabilities = KzgCommitmentAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut plonk_circuit_bug_vulnerabilities = PlonkCircuitBugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut threshold_signature_attack_vulnerabilities = ThresholdSignatureAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut zk_email_advanced_vulnerabilities = ZkEmailAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let fhe_sidechannel_vulnerabilities = FheSidechannelDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        modules_run += 56;
        
        // === ADDITIONAL CRITICAL DETECTORS (25 INSTANTIATIONS) - SESSION 2 ===
        let timelock_bypass_vulnerabilities = TimelockBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let vote_buying_detection_vulnerabilities = VoteBuyingDetectionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut late_quorum_extension_griefing_vulnerabilities = LateQuorumExtensionGriefingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut proposal_spam_dos_vulnerabilities = ProposalSpamDosDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut cross_function_reentrancy_vulnerabilities = CrossFunctionReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let create_reentrancy_vulnerabilities = CreateReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut storage_gap_missing_vulnerabilities = StorageGapMissingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut unstructured_storage_collision_vulnerabilities = UnstructuredStorageCollisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut sequencer_downtime_exploit_vulnerabilities = SequencerDowntimeExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut multi_oracle_disagreement_vulnerabilities = MultiOracleDisagreementDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut oracle_circuit_breaker_bypass_vulnerabilities = OracleCircuitBreakerBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut pausable_token_funds_locked_vulnerabilities = PausableTokenFundsLockedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let blocklist_token_usdc_vulnerabilities = BlocklistTokenUsdcDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let circular_protocol_dependency_vulnerabilities = CircularProtocolDependencyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let double_initialization_attack_vulnerabilities = DoubleInitializationAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let eip712_domain_phishing_vulnerabilities = Eip712DomainPhishingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut priority_fee_manipulation_vulnerabilities = PriorityFeeManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let create2_metamorphic_state_vulnerabilities = Create2MetamorphicStateDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let capability_based_escalation_vulnerabilities = CapabilityBasedEscalationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut permit_deadline_manipulation_vulnerabilities = PermitDeadlineManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut time_bandit_reorg_vulnerabilities = TimeBanditReorgDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut exp_taylor_overflow_vulnerabilities = ExpTaylorOverflowDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut sqrt_newton_nonconvergence_vulnerabilities = SqrtNewtonNonconvergenceDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut role_hierarchy_violation_vulnerabilities = RoleHierarchyViolationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let builder_exclusive_orderflow_vulnerabilities = BuilderExclusiveOrderflowDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let delayed_inbox_censorship_vulnerabilities = DelayedInboxCensorshipDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut permission_escalation_advanced_vulnerabilities = PermissionEscalationAdvancedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let eip1271_recursive_validation_vulnerabilities = Eip1271RecursiveValidationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut ecrecover_zero_address_vulnerabilities = EcrecoverZeroAddressDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let compact_signature_vulnerabilities = CompactSignatureEip2098Detector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bn254_pairing_dos_vulnerabilities = Bn254PairingDosDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut signature_s_value_malleability_vulnerabilities = SignatureSValueMalleabilityDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let fraud_proof_timeout_vulnerabilities = FraudProofTimeoutDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut zk_circuit_underconstrained_vulnerabilities = ZkCircuitUnderconstrainedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut validity_proof_bypass_vulnerabilities = ValidityProofBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let compressed_calldata_bomb_vulnerabilities = CompressedCalldataBombDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let jit_liquidity_sandwich_vulnerabilities = JitLiquiditySandwichDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let impermanent_loss_attack_vulnerabilities = ImpermanentLossAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut vault_inflation_first_deposit_vulnerabilities = VaultInflationFirstDepositDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let donate_to_pool_attack_vulnerabilities = DonateToPoolAttackDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let returndatacopy_bomb_vulnerabilities = ReturndatacopyBombDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let calldata_expansion_dos_vulnerabilities = CalldataExpansionDosDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let sstore_refund_exploit_vulnerabilities = SstoreRefundExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc4337_storage_collision_vulnerabilities = Erc4337StorageCollisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let paymaster_context_manipulation_vulnerabilities = PaymasterContextManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let bundler_dos_vulnerabilities = BundlerDosDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc1155_batch_overflow_vulnerabilities = Erc1155BatchOverflowDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc2612_permit_frontrun_vulnerabilities = Erc2612PermitFrontrunDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc5192_soulbound_bypass_vulnerabilities = Erc5192SoulboundBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let chainlink_stale_price_vulnerabilities = ChainlinkStalePriceDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let twap_manipulation_short_window_vulnerabilities = TwapManipulationShortWindowDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let oracle_price_deviation_vulnerabilities = OraclePriceDeviationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let rebasing_token_accounting_vulnerabilities = RebasingTokenAccountingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let double_entry_point_token_vulnerabilities = DoubleEntryPointTokenDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let deflationary_token_vulnerabilities = DeflationaryTokenDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let curve_vyper_reentrancy_vulnerabilities = CurveVyperReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let balancer_vault_reentrancy_vulnerabilities = BalancerVaultReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let aave_liquidation_manipulation_vulnerabilities = AaveLiquidationManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let transparent_proxy_selector_clash_vulnerabilities = TransparentProxySelectorClashDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let beacon_proxy_implementation_vulnerabilities = BeaconProxyImplementationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let uups_authorization_bypass_vulnerabilities = UupsAuthorizationBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let diamond_storage_collision_vulnerabilities = DiamondStorageCollisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let flash_loan_voting_vulnerabilities = FlashLoanVotingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let governor_bravo_threshold_vulnerabilities = GovernorBravoThresholdDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let timelock_frontrun_vulnerabilities = TimelockFrontrunDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let phantom_overflow_vulnerabilities = PhantomOverflowDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let precision_loss_multiplication_division_order_vulnerabilities = PrecisionLossMultiplicationDivisionOrderDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let sqrt_rounding_manipulation_vulnerabilities = SqrtRoundingManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let fixed_point_math_truncation_vulnerabilities = FixedPointMathTruncationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let block_gas_limit_dos_vulnerabilities = BlockGasLimitDosDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let unbounded_loop_array_vulnerabilities = UnboundedLoopArrayDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let storage_exhaustion_vulnerabilities = StorageExhaustionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let merkle_tree_second_preimage_vulnerabilities = MerkleTreeSecondPreimageDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let wormhole_guardian_manipulation_vulnerabilities = WormholeGuardianManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let multicall_msg_value_reuse_vulnerabilities = MulticallMsgValueReuseDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let delegatecall_selector_collision_vulnerabilities = DelegatecallSelectorCollisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();

        // === CRITICAL MISSING DETECTORS (30 NEW) ===
        let erc20_approve_race_condition_vulnerabilities = Erc20ApproveRaceConditionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let erc20_transfer_return_unchecked_vulnerabilities = Erc20TransferReturnUncheckedDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let cross_chain_keeper_bypass_vulnerabilities = CrossChainKeeperBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let array_delete_bug_vulnerabilities = ArrayDeleteBugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let unchecked_downcast_vulnerabilities = UncheckedDowncastDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let zero_division_vulnerabilities = ZeroDivisionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let constructor_in_upgradeable_vulnerabilities = ConstructorInUpgradeableDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let missing_initializer_modifier_vulnerabilities = MissingInitializerModifierDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let two_step_ownership_transfer_vulnerabilities = TwoStepOwnershipTransferDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let eip712_domain_chainid_missing_vulnerabilities = Eip712DomainChainidMissingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut signature_nonce_missing_vulnerabilities = SignatureNonceMissingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut spot_price_manipulation_vulnerabilities = SpotPriceManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut oracle_precision_loss_vulnerabilities = OraclePrecisionLossDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut rounding_direction_exploit_vulnerabilities = RoundingDirectionExploitDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut eth_send_failure_vulnerabilities = EthSendFailureDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut locked_ether_vulnerabilities = LockedEtherDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut assert_vs_require_vulnerabilities = AssertVsRequireDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut floating_pragma_vulnerabilities = FloatingPragmaDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut sandwich_attack_susceptibility_vulnerabilities = SandwichAttackSusceptibilityDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut liquidity_removal_race_vulnerabilities = LiquidityRemovalRaceDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut vault_share_price_manipulation_vulnerabilities = VaultSharePriceManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut bridge_message_replay_vulnerabilities = BridgeMessageReplayDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut userop_signature_replay_vulnerabilities = UseropSignatureReplayDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut paymaster_gas_drain_vulnerabilities = PaymasterGasDrainDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut proposal_execution_delay_bypass_vulnerabilities = ProposalExecutionDelayBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut quorum_manipulation_vulnerabilities = QuorumManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut erc721_onerc721received_missing_vulnerabilities = Erc721Onerc721receivedMissingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut nft_metadata_manipulation_vulnerabilities = NftMetadataManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let emergency_stop_missing_vulnerabilities = EmergencyStopMissingDetector::new(self.bytecode.clone()).detect_vulnerabilities();

        // === ADDITIONAL CRITICAL DETECTORS (27 NEW) ===
        let mut tax_token_manipulation_vulnerabilities = TaxTokenManipulationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut abi_encoder_v2_bug_vulnerabilities = AbiEncoderV2BugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut optimizer_bug_vulnerabilities = OptimizerBugDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut incorrect_decimal_handling_vulnerabilities = IncorrectDecimalHandlingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut missing_critical_events_vulnerabilities = MissingCriticalEventsDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut interface_confusion_vulnerabilities = InterfaceConfusionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut fallback_receive_exploitation_vulnerabilities = FallbackReceiveExploitationDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut function_shadowing_vulnerabilities = FunctionShadowingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut create2_frontrunning_vulnerabilities = Create2FrontrunningDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let initialization_race_condition_vulnerabilities = InitializationRaceConditionDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut wrong_address_constant_vulnerabilities = WrongAddressConstantDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let max_transaction_bypass_vulnerabilities = MaxTransactionBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut blacklist_bypass_vulnerabilities = BlacklistBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut erc1155_callback_reentrancy_vulnerabilities = Erc1155CallbackReentrancyDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut reflection_token_accounting_vulnerabilities = ReflectionTokenAccountingDetector::new(self.bytecode.clone()).detect_vulnerabilities();
        let mut liquidity_lock_bypass_vulnerabilities = LiquidityLockBypassDetector::new(self.bytecode.clone()).detect_vulnerabilities();
