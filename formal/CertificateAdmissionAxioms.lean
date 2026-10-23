-- CI audit: the ADR-015 theorems depend only on Lean's standard axioms (propext, Quot.sound,
-- Classical.choice). The workflow fails if any other axiom appears in this output.
import CertificateAdmission
open BSB.Admission
#print axioms client_safety
#print axioms provider_safety
#print axioms provider_liveness
#print axioms late_refutation_can_lose
#print axioms hidden_path_breaks_safety
#print axioms journal_ge
#print axioms weaker_never_replaces
#print axioms fixed_graph_misses
#print axioms enumerated_leaf_incomplete
#print axioms copy_redirect
#print axioms presigned_binds
#print axioms outsider_exists
#print axioms truthful_keeps_bond
#print axioms underclaim_forfeits
