import TDN.Import.Command
import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

tdn_data snapshot : Evidence.Snapshot from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.snapshot"]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

tdn_data chain_BLACK_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters4_INPUT"]

tdn_data chain_BLACK_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters4_FORWARD"]

tdn_data chain_BLACK_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters4_OUTPUT"]

tdn_data chain_BLACK_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters6_INPUT"]

tdn_data chain_BLACK_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters6_FORWARD"]

tdn_data chain_BLACK_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_BLACK_filters6_OUTPUT"]

tdn_data chain_GF_A_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters4_INPUT"]

tdn_data chain_GF_A_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters4_FORWARD"]

tdn_data chain_GF_A_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters4_OUTPUT"]

tdn_data chain_GF_A_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters6_INPUT"]

tdn_data chain_GF_A_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters6_FORWARD"]

tdn_data chain_GF_A_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_A_filters6_OUTPUT"]

tdn_data chain_R_A1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters4_INPUT"]

tdn_data chain_R_A1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters4_FORWARD"]

tdn_data chain_R_A1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters4_OUTPUT"]

tdn_data chain_R_A1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters6_INPUT"]

tdn_data chain_R_A1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters6_FORWARD"]

tdn_data chain_R_A1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A1_filters6_OUTPUT"]

tdn_data chain_I_A1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters4_INPUT"]

tdn_data chain_I_A1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters4_FORWARD"]

lemma chain_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A1_filters4_FORWARD; decide

theorem chain_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A1_filters4_FORWARD "red" "gray" chain_I_A1_filters4_FORWARD_guarded p accepted

tdn_data chain_I_A1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters4_OUTPUT"]

tdn_data chain_I_A1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters6_INPUT"]

tdn_data chain_I_A1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters6_FORWARD"]

tdn_data chain_I_A1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A1_filters6_OUTPUT"]

tdn_data chain_G_A1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters4_INPUT"]

tdn_data chain_G_A1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters4_FORWARD"]

tdn_data chain_G_A1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters4_OUTPUT"]

tdn_data chain_G_A1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters6_INPUT"]

tdn_data chain_G_A1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters6_FORWARD"]

tdn_data chain_G_A1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A1_filters6_OUTPUT"]

tdn_data chain_O_A1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters4_INPUT"]

tdn_data chain_O_A1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters4_FORWARD"]

lemma chain_O_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_O_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_A1_filters4_FORWARD; decide

theorem chain_O_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_A1_filters4_FORWARD "gray" "black" chain_O_A1_filters4_FORWARD_guarded p accepted

tdn_data chain_O_A1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters4_OUTPUT"]

tdn_data chain_O_A1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters6_INPUT"]

tdn_data chain_O_A1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters6_FORWARD"]

tdn_data chain_O_A1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A1_filters6_OUTPUT"]

tdn_data chain_OF_A1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters4_INPUT"]

tdn_data chain_OF_A1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters4_FORWARD"]

tdn_data chain_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters4_OUTPUT"]

tdn_data chain_OF_A1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters6_INPUT"]

tdn_data chain_OF_A1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters6_FORWARD"]

tdn_data chain_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A1_filters6_OUTPUT"]

tdn_data chain_R_A2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters4_INPUT"]

tdn_data chain_R_A2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters4_FORWARD"]

tdn_data chain_R_A2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters4_OUTPUT"]

tdn_data chain_R_A2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters6_INPUT"]

tdn_data chain_R_A2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters6_FORWARD"]

tdn_data chain_R_A2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_A2_filters6_OUTPUT"]

tdn_data chain_I_A2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters4_INPUT"]

tdn_data chain_I_A2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters4_FORWARD"]

lemma chain_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A2_filters4_FORWARD; decide

theorem chain_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A2_filters4_FORWARD "red" "gray" chain_I_A2_filters4_FORWARD_guarded p accepted

tdn_data chain_I_A2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters4_OUTPUT"]

tdn_data chain_I_A2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters6_INPUT"]

tdn_data chain_I_A2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters6_FORWARD"]

tdn_data chain_I_A2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_A2_filters6_OUTPUT"]

tdn_data chain_G_A2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters4_INPUT"]

tdn_data chain_G_A2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters4_FORWARD"]

tdn_data chain_G_A2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters4_OUTPUT"]

tdn_data chain_G_A2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters6_INPUT"]

tdn_data chain_G_A2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters6_FORWARD"]

tdn_data chain_G_A2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_A2_filters6_OUTPUT"]

tdn_data chain_O_A2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters4_INPUT"]

tdn_data chain_O_A2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters4_FORWARD"]

lemma chain_O_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_O_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_A2_filters4_FORWARD; decide

theorem chain_O_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_A2_filters4_FORWARD "gray" "black" chain_O_A2_filters4_FORWARD_guarded p accepted

tdn_data chain_O_A2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters4_OUTPUT"]

tdn_data chain_O_A2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters6_INPUT"]

tdn_data chain_O_A2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters6_FORWARD"]

tdn_data chain_O_A2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_A2_filters6_OUTPUT"]

tdn_data chain_OF_A2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters4_INPUT"]

tdn_data chain_OF_A2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters4_FORWARD"]

tdn_data chain_OF_A2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters4_OUTPUT"]

tdn_data chain_OF_A2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters6_INPUT"]

tdn_data chain_OF_A2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters6_FORWARD"]

tdn_data chain_OF_A2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_A2_filters6_OUTPUT"]

tdn_data chain_GF_B_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters4_INPUT"]

tdn_data chain_GF_B_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters4_FORWARD"]

tdn_data chain_GF_B_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters4_OUTPUT"]

tdn_data chain_GF_B_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters6_INPUT"]

tdn_data chain_GF_B_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters6_FORWARD"]

tdn_data chain_GF_B_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_GF_B_filters6_OUTPUT"]

tdn_data chain_R_B1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters4_INPUT"]

tdn_data chain_R_B1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters4_FORWARD"]

tdn_data chain_R_B1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters4_OUTPUT"]

tdn_data chain_R_B1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters6_INPUT"]

tdn_data chain_R_B1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters6_FORWARD"]

tdn_data chain_R_B1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B1_filters6_OUTPUT"]

tdn_data chain_I_B1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters4_INPUT"]

tdn_data chain_I_B1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters4_FORWARD"]

lemma chain_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B1_filters4_FORWARD; decide

theorem chain_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B1_filters4_FORWARD "red" "gray" chain_I_B1_filters4_FORWARD_guarded p accepted

tdn_data chain_I_B1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters4_OUTPUT"]

tdn_data chain_I_B1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters6_INPUT"]

tdn_data chain_I_B1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters6_FORWARD"]

tdn_data chain_I_B1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B1_filters6_OUTPUT"]

tdn_data chain_G_B1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters4_INPUT"]

tdn_data chain_G_B1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters4_FORWARD"]

tdn_data chain_G_B1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters4_OUTPUT"]

tdn_data chain_G_B1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters6_INPUT"]

tdn_data chain_G_B1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters6_FORWARD"]

tdn_data chain_G_B1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B1_filters6_OUTPUT"]

tdn_data chain_O_B1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters4_INPUT"]

tdn_data chain_O_B1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters4_FORWARD"]

lemma chain_O_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_O_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_B1_filters4_FORWARD; decide

theorem chain_O_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_B1_filters4_FORWARD "gray" "black" chain_O_B1_filters4_FORWARD_guarded p accepted

tdn_data chain_O_B1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters4_OUTPUT"]

tdn_data chain_O_B1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters6_INPUT"]

tdn_data chain_O_B1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters6_FORWARD"]

tdn_data chain_O_B1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B1_filters6_OUTPUT"]

tdn_data chain_OF_B1_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters4_INPUT"]

tdn_data chain_OF_B1_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters4_FORWARD"]

tdn_data chain_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters4_OUTPUT"]

tdn_data chain_OF_B1_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters6_INPUT"]

tdn_data chain_OF_B1_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters6_FORWARD"]

tdn_data chain_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B1_filters6_OUTPUT"]

tdn_data chain_R_B2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters4_INPUT"]

tdn_data chain_R_B2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters4_FORWARD"]

tdn_data chain_R_B2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters4_OUTPUT"]

tdn_data chain_R_B2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters6_INPUT"]

tdn_data chain_R_B2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters6_FORWARD"]

tdn_data chain_R_B2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_R_B2_filters6_OUTPUT"]

tdn_data chain_I_B2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters4_INPUT"]

tdn_data chain_I_B2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters4_FORWARD"]

lemma chain_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B2_filters4_FORWARD; decide

theorem chain_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B2_filters4_FORWARD "red" "gray" chain_I_B2_filters4_FORWARD_guarded p accepted

tdn_data chain_I_B2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters4_OUTPUT"]

tdn_data chain_I_B2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters6_INPUT"]

tdn_data chain_I_B2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters6_FORWARD"]

tdn_data chain_I_B2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_I_B2_filters6_OUTPUT"]

tdn_data chain_G_B2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters4_INPUT"]

tdn_data chain_G_B2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters4_FORWARD"]

tdn_data chain_G_B2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters4_OUTPUT"]

tdn_data chain_G_B2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters6_INPUT"]

tdn_data chain_G_B2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters6_FORWARD"]

tdn_data chain_G_B2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_G_B2_filters6_OUTPUT"]

tdn_data chain_O_B2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters4_INPUT"]

tdn_data chain_O_B2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters4_FORWARD"]

lemma chain_O_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_O_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_B2_filters4_FORWARD; decide

theorem chain_O_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_B2_filters4_FORWARD "gray" "black" chain_O_B2_filters4_FORWARD_guarded p accepted

tdn_data chain_O_B2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters4_OUTPUT"]

tdn_data chain_O_B2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters6_INPUT"]

tdn_data chain_O_B2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters6_FORWARD"]

tdn_data chain_O_B2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_O_B2_filters6_OUTPUT"]

tdn_data chain_OF_B2_filters4_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters4_INPUT"]

tdn_data chain_OF_B2_filters4_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters4_FORWARD"]

tdn_data chain_OF_B2_filters4_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters4_OUTPUT"]

tdn_data chain_OF_B2_filters6_INPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters6_INPUT"]

tdn_data chain_OF_B2_filters6_FORWARD : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters6_FORWARD"]

tdn_data chain_OF_B2_filters6_OUTPUT : List PacketPolicy.Rule from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.chain_OF_B2_filters6_OUTPUT"]

tdn_data observedESPHardLifetimes : List Evidence.HardLifetimeFact from "../../evidence/lean/Adjacency.json" ["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z.observedESPHardLifetimes"]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

end TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z
