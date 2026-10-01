% Keep the base program satisfiable even when a property fails, so failures
% remain visible. Activate exactly one external to ask for a counterexample.
% A consistent base model is checked first: inconsistency is never a proof.
#external check(P) : property(P,_).
:- check(P), not failed(P).
counterexample(P,S,D) :- check(P), violation(P,S,D).

% For direct command-line queries: -c target=site_a_gray_cut.
% The default target all evaluates all checks without requiring a failure.
#const target=all.
requested(P) :- property(P,_), P = target, target != all.
:- requested(P), not failed(P).
counterexample(P,S,D) :- requested(P), violation(P,S,D).
invalid_query(target) :- target != all, not requested(_).
#show invalid_query/1.
