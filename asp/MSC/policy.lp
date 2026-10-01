% Rules are ACCEPT-only, followed by a chain default. Optional matches appear
% as separate named facts. Their absence means wildcard, not missing evidence.
% Missing entire tables remain unknown. Policy tags use none / some(Reqid).
% ipv4(A,B,C,D) terms compare lexicographically; all octets are 0..255.
% No 32-bit packed integer is used: clingo integers cannot hold all IPv4 values.
guarded_rule(D,R) :- requires_policy(D,R,_,_).
has_rule(D) :- forward_rule(D,_).
has_unguarded_rule(D) :- forward_rule(D,R), not guarded_rule(D,R).
guarded_table(D) :- forward_table(D,drop), not has_unguarded_rule(D).
denies_all(D) :- forward_table(D,drop), not has_rule(D).
untagged_may_accept(D) :- forward_table(D,accept).
untagged_may_accept(D) :- has_unguarded_rule(D).

has_ports(D,R) :- destination_port(D,R,_).
port_match(D,R,P) :- destination_port(D,R,P).

% A case fails a rule if any specified field disagrees. Each mismatch is
% grounded only for an actual query and actual rule on the same device.
mismatch(Q,D,R) :- packet_case(Q,D,I,_,_,_,_,_,_,_), forward_rule(D,R), input_interface(D,R,J), I != J.
mismatch(Q,D,R) :- packet_case(Q,D,_,O,_,_,_,_,_,_), forward_rule(D,R), output_interface(D,R,J), O != J.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,S,_,_,_,_,_), source_range(D,R,L,_), S < L.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,S,_,_,_,_,_), source_range(D,R,_,H), S > H.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,T,_,_,_,_), destination_range(D,R,L,_), T < L.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,T,_,_,_,_), destination_range(D,R,_,H), T > H.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,_,P,_,_,_), protocol(D,R,J), P != J.
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,_,_,P,_,_), has_ports(D,R), not port_match(D,R,P).
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,_,_,_,I,_), requires_policy(D,R,in,J), I != some(J).
mismatch(Q,D,R) :- packet_case(Q,D,_,_,_,_,_,_,_,O), requires_policy(D,R,out,J), O != some(J).
rule_matches(Q,D,R) :- packet_case(Q,D,_,_,_,_,_,_,_,_), forward_rule(D,R), not mismatch(Q,D,R).
accepted(Q,D) :- rule_matches(Q,D,_).
accepted(Q,D) :- packet_case(Q,D,_,_,_,_,_,_,_,_), forward_table(D,accept).
has_table(D) :- forward_table(D,_).
decision(Q,D,accept) :- accepted(Q,D), has_table(D).
decision(Q,D,drop) :- packet_case(Q,D,_,_,_,_,_,_,_,_), has_table(D), not accepted(Q,D).
decision(Q,D,unknown) :- packet_case(Q,D,_,_,_,_,_,_,_,_), not has_table(D).
