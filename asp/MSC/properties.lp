% Each query describes a violation. A completed, empty violation relation is
% a finite-model result. It is not an independently checked Lean proof term.
violation(device_count, "inventory", N) :- N = #count { I,D : device_row(I,D) }, N != 35.
violation(link_count, "inventory", N) :- N = #count { I,A,AP,B,BP,Z : link(I,A,AP,B,BP,Z) }, N != 44.
violation(device_ids_unique,D,"duplicate") :- device_row(I,D),device_row(J,D),I != J.
violation(cable_endpoints_valid,A,AP) :- cable(A,AP,_,_,Z), not interface(A,AP,Z,_).
violation(red_hosts_attach_to_inner,A,B) :- cable(A,_,B,_,_),role(A,host),not role(B,inner).
violation(red_hosts_attach_to_inner,A,Z) :- cable(A,_,_,_,Z),role(A,host),Z != red.
violation(gray_edges_preserve_label,A,B) :- bad_gray_edge(A,B).
violation(no_cross_level_gray_bypass,A,B) :- gray_reach(A,B),different_gray_label(A,B).
% Only the current graph/label instance of the generic implication is checked.
violation(walk_preserves,A,B) :- gray_reach(A,B),different_gray_label(A,B),not some_bad_gray_edge.
violation(site_a_gray_cut,"I_A1","I_A2") :- gray_reach("I_A1","I_A2").
violation(site_b_gray_cut,"I_B1","I_B2") :- gray_reach("I_B1","I_B2").
violation(management_edges_preserve_domain,A,B) :- management_edge(A,B),management_domain(A,X),management_domain(B,Y),X != Y.
violation(no_cross_domain_management_cable_path,A,B) :- management_reach(A,B),management_domain(A,X),management_domain(B,Y),X != Y.
violation(inner_outer_admin_separate,"AW_A1","O_A1") :- management_reach("AW_A1","O_A1").
violation(tunnel_peers_symmetric,D,P) :- tunnel(D,P,_,_,_,_,_,_),not reverse_tunnel(D).
violation(inner_peers_same_level,D,P) :- tunnel(D,P,_,_,_,_,_,_),role(D,inner),level(D,X),level(P,Y),X != Y.
violation(inner_trust_domains_separate,D,P) :- tunnel(D,_,_,_,_,_,T,_),tunnel(P,_,_,_,_,_,T,_),role(D,inner),role(P,inner),level(D,X),level(P,Y),X != Y.
violation(sampled_devices_running,D,"not running") :- observation(D,_,false,_,_,_).
violation(sampled_devices_running,D,"observation errors") :- observation(D,_,_,_,E,_),E != 0.
violation(sampled_devices_running,D,"wrong identity") :- observation(D,_,_,S,_,_),evidence(T,_,_,_,_),S != T.
violation(sampled_tunnels_established,D,"down or unknown") :- observation(D,_,_,_,_,UP),encryptor(D),UP != established.
violation(sampled_probe_report_passed,"probes","failed") :- evidence(_,_,_,_,0).
violation(sampled_probe_report_passed,"probes",N) :- evidence(_,_,_,N,_),N != 273.

% Generic rule/table theorems become instance checks plus structural conditions.
violation(protected_rule_blocks_untagged,D,Q) :- rule_matches(Q,D,R),guarded_rule(D,R),packet_case(Q,D,_,_,_,_,_,_,none,none).
violation(protected_table_blocks_untagged,D,Q) :- guarded_table(D),decision(Q,D,accept),packet_case(Q,D,_,_,_,_,_,_,none,none).
violation(encryptor_tables_guarded,D,"default accept or unguarded rule") :- encryptor(D),not guarded_table(D).
violation(encryptor_without_policy_drops,D,"untagged acceptance possible") :- encryptor(D),untagged_may_accept(D).
violation(gray_firewall_denies_all,"GF_A","not an empty default-drop table") :- not denies_all("GF_A").
violation(gray_firewall_denies_all,"GF_B","not an empty default-drop table") :- not denies_all("GF_B").
violation(outer_firewall_accepts_declared_esp,"OF_A1","esp") :- not decision("esp","OF_A1",accept).
violation(outer_firewall_rejects_icmp,"OF_A1","icmp") :- not decision("icmp","OF_A1",drop).
violation(outer_firewall_rejects_wrong_peer,"OF_A1","wrong-peer") :- not decision("wrong-peer","OF_A1",drop).

violation(host_labels_match_snapshot,D,L) :- host(D,L),not level(D,L).
violation(authorized_same_level,A,B) :- authorized(A,B),different_host_level(A,B).
violation(cross_level_blocked,A,B) :- transmitted(_,A,B),different_host_level(A,B).
violation(unauthorized_peer_blocked,A,B) :- transmitted(_,A,B),not authorized(A,B).
violation(inner_failure_closed,A,B) :- transmitted(S,A,B),state(S,0,_,_,_,_,_,_,_,_).
violation(inner_policy_loss_closed,A,B) :- transmitted(S,A,B),state(S,_,_,_,_,0,_,_,_,_).
violation(inner_authentication_failure_closed,A,B) :- transmitted(S,A,B),state(S,_,_,0,_,_,_,_,_,_).
violation(outer_failure_closed,A,B) :- transmitted(S,A,B),state(S,_,0,_,_,_,_,_,_,_).
violation(outer_policy_loss_closed,A,B) :- transmitted(S,A,B),state(S,_,_,_,_,_,0,_,_,_).
violation(outer_authentication_failure_closed,A,B) :- transmitted(S,A,B),state(S,_,_,_,0,_,_,_,_,_).
violation(transport_failure_blocks,A,B) :- transmitted(S,A,B),state(S,_,_,_,_,_,_,0,_,_).
violation(forwarded_has_both_steps,A,B) :- transmitted(S,A,B),not inner_encrypted(S,A,B).
violation(forwarded_has_both_steps,A,B) :- transmitted(S,A,B),not outer_encrypted(S,A,B).
violation(forwarded_same_level,A,B) :- transmitted(_,A,B),different_host_level(A,B).
violation(delivered_has_decryption_steps,A,B) :- delivered(S,R,A,B),not delivery_witness(S,R,A,B).
violation(cross_level_not_delivered,A,B) :- delivered(_,_,A,B),different_host_level(A,B).
violation(receiver_inner_failure_closed,A,B) :- delivered(_,R,A,B),state(R,0,_,_,_,_,_,_,_,_).
violation(receiver_outer_failure_closed,A,B) :- delivered(_,R,A,B),state(R,_,0,_,_,_,_,_,_,_).
violation(ready_authorized_forwards,A,B) :- authorized(A,B),host(A,_),host(B,_),not transmitted(511,A,B).
violation(ready_authorized_delivers,A,B) :- authorized(A,B),host(A,_),host(B,_),not delivered(511,511,A,B).

% Report every property explicitly. Input validation and the runner also check
% inventory completeness, so an empty file is never mistaken for full success.
failed(N) :- violation(N,_,_).
result(N,pass,S) :- property(N,S),not failed(N).
result(N,fail,S) :- property(N,S),failed(N).

% Domain counts guard against accidentally dropping states or packet cases.
statistics(states,N) :- N = #count { S : state(S,_,_,_,_,_,_,_,_,_) }.
statistics(devices,N) :- N = #count { I,D : device_row(I,D) }.
statistics(links,N) :- N = #count { I,A,AP,B,BP,Z : link(I,A,AP,B,BP,Z) }.
statistics(host_pairs,N) :- N = #count { A,B : host(A,_),host(B,_) }.
statistics(transmitted,N) :- N = #count { S,A,B : transmitted(S,A,B) }.
statistics(delivered,N) :- N = #count { S,R,A,B : delivered(S,R,A,B) }.
