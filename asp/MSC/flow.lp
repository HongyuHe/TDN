% Exactly the nine Boolean fields of Lean GatewayState. State IDs are bitmasks
% for hypothetical inputs, not inferred health observations from the snapshot.
bit(0;1).
state(A+2*B+4*C+8*D+16*E+32*F+64*G+128*H+256*I,A,B,C,D,E,F,G,H,I) :-
    bit(A),bit(B),bit(C),bit(D),bit(E),bit(F),bit(G),bit(H),bit(I).
inner_ready(S) :- state(S,1,_,1,_,1,_,_,_,_).
outer_send_ready(S) :- state(S,_,1,_,1,_,1,1,1,1).
outer_receive_ready(S) :- state(S,_,1,_,1,_,1,_,_,_).

% Payload is opaque because Lean's guards never inspect it. Stages preserve
% its identity; neither implementation proves computational secrecy.
inner_encrypted(S,A,B) :- inner_ready(S), authorized(A,B), host(A,_), host(B,_).
outer_encrypted(S,A,B) :- inner_encrypted(S,A,B), outer_send_ready(S).
transmitted(S,A,B) :- outer_encrypted(S,A,B).
outer_decrypted(S,R,A,B) :- transmitted(S,A,B), outer_receive_ready(R).
inner_decrypted(S,R,A,B) :- outer_decrypted(S,R,A,B), inner_ready(R).
delivered(S,R,A,B) :- inner_decrypted(S,R,A,B).
delivery_witness(S,R,A,B) :- inner_encrypted(S,A,B), outer_encrypted(S,A,B), transmitted(S,A,B), outer_decrypted(S,R,A,B), inner_decrypted(S,R,A,B), delivered(S,R,A,B).
