% device(Name, Role, Site, Level) records declared logical components.
% The atom none preserves missing labels; S1/S2 have no numeric ordering.
node(D) :- device(D,_,_,_).
role(D,R) :- device(D,R,_,_).
level(D,L) :- device(D,_,_,L).
gray_label(D,S,L) :- device(D,_,S,L), S != none, L != none.
gray_label(D,none,none) :- device(D,_,none,_).
gray_label(D,none,none) :- device(D,_,_,none).

% A virtual cable has two directions. Gray reachability removes Gray Firewalls
% to ask whether a path can bypass them, rather than whether packets deliver.
cable(A,AP,B,BP,Z) :- link(_,A,AP,B,BP,Z).
cable(B,BP,A,AP,Z) :- link(_,A,AP,B,BP,Z).
gray_edge(A,B) :- cable(A,_,B,_,gray), not role(A,gray_firewall), not role(B,gray_firewall).
management_edge(A,B) :- cable(A,_,B,_,management).
gray_reach(A,A) :- node(A).
gray_reach(A,C) :- gray_edge(A,B), gray_reach(B,C).
management_reach(A,A) :- node(A).
management_reach(A,C) :- management_edge(A,B), management_reach(B,C).
different_gray_label(A,B) :- gray_label(A,S,_), gray_label(B,T,_), S != T.
different_gray_label(A,B) :- gray_label(A,_,L), gray_label(B,_,M), L != M.
bad_gray_edge(A,B) :- gray_edge(A,B), different_gray_label(A,B).
some_bad_gray_edge :- bad_gray_edge(_,_).

% These four constructors match Lean RedHost. Adding a host requires an
% intentional model extension, not just an unreviewed new device declaration.
host("R_A1","S1"). host("R_A2","S2").
host("R_B1","S1"). host("R_B2","S2").
different_host_level(A,B) :- host(A,L), host(B,M), L != M.
encryptor(D) :- role(D,inner).
encryptor(D) :- role(D,outer).
reverse_tunnel(D) :- tunnel(D,P,A,B,X,Y,T,R), tunnel(P,D,B,A,Y,X,T,R).
