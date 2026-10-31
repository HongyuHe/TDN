import TDN.Import.Command
import TDN.Evidence.FreshFamily644

namespace TDN.Imported.Family644
open Execution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option linter.unusedSimpArgs false

tdn_data witnessState0 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState0"]

tdn_data witnessState1 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState1"]

tdn_data witnessState2 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState2"]

tdn_data witnessState3 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState3"]

tdn_data witnessState4 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState4"]

tdn_data witnessState5 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState5"]

tdn_data witnessState6 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState6"]

tdn_data witnessState7 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState7"]

tdn_data witnessState8 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState8"]

tdn_data witnessState9 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState9"]

tdn_data witnessState10 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState10"]

tdn_data witnessState11 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState11"]

tdn_data witnessState12 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState12"]

tdn_data witnessState13 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState13"]

tdn_data witnessState14 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState14"]

tdn_data witnessState15 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState15"]

tdn_data witnessState16 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState16"]

tdn_data witnessState17 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState17"]

tdn_data witnessState18 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState18"]

tdn_data witnessState19 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState19"]

tdn_data witnessState20 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState20"]

tdn_data witnessState21 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState21"]

tdn_data witnessState22 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState22"]

tdn_data witnessState23 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState23"]

tdn_data witnessState24 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState24"]

tdn_data witnessState25 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState25"]

tdn_data witnessState26 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState26"]

tdn_data witnessState27 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState27"]

tdn_data witnessState28 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState28"]

tdn_data witnessState29 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState29"]

tdn_data witnessState30 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState30"]

tdn_data witnessState31 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState31"]

tdn_data witnessState32 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState32"]

tdn_data witnessState33 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState33"]

tdn_data witnessState34 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState34"]

tdn_data witnessState35 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState35"]

tdn_data witnessState36 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState36"]

tdn_data witnessState37 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState37"]

tdn_data witnessState38 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState38"]

tdn_data witnessState39 : Execution.State from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessState39"]

lemma witness_immediate_header_checks : witnessState4.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ True := by decide

lemma witnessStep0 : Execution.Step config witnessState0 .route witnessState1 := by
  exact Execution.Step.outputRoute ⟨7, 7, 676660126762715061578622956811050811392, 676660126762715061597069700884760363007, 64, 1024, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep1 : Execution.Step config witnessState1 .filter witnessState2 := by
  exact Execution.Step.outputFilter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep2 : Execution.Step config witnessState2 .local witnessState3 := by
  exact Execution.Step.plain (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep3 : Execution.Step config witnessState3 .wire witnessState4 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep4 : Execution.Step config witnessState4 .local witnessState5 := by
  exact Execution.Step.receive "NEW"

lemma witnessStep5 : Execution.Step config witnessState5 .route witnessState6 := by
  exact Execution.Step.route ⟨12, 10, 676660126762715061578622956811050811392, 676660126762715061597069700884760363007, 64, 1024, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep6 : Execution.Step config witnessState6 .filter witnessState7 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep7 : Execution.Step config witnessState7 .encrypt witnessState8 := by
  exact Execution.Step.encrypt ⟨100, 1, 168493057, 169148417, 676660126683486899064358619217506861056, 676660126683486899082805363291216412671, 676660126762715061578622956811050811392, 676660126762715061597069700884760363007, 0, none⟩ ⟨100, 1001, 168493057, 169148417⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep8 : Execution.Step config witnessState8 .route witnessState9 := by
  exact Execution.Step.outerRoute ⟨10, 10, 169148417, 169148417, 32, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep9 : Execution.Step config witnessState9 .wire witnessState10 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep10 : Execution.Step config witnessState10 .local witnessState11 := by
  exact Execution.Step.receive "NEW"

lemma witnessStep11 : Execution.Step config witnessState11 .route witnessState12 := by
  exact Execution.Step.route ⟨17, 16, 169148417, 169148417, 32, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep12 : Execution.Step config witnessState12 .filter witnessState13 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep13 : Execution.Step config witnessState13 .encrypt witnessState14 := by
  exact Execution.Step.encrypt ⟨200, 2, 3221225985, 3221226241, 168493057, 168493057, 169148417, 169148417, 0, none⟩ ⟨200, 2001, 3221225985, 3221226241⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep14 : Execution.Step config witnessState14 .route witnessState15 := by
  exact Execution.Step.outerRoute ⟨16, 16, 3221226241, 3221226241, 32, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep15 : Execution.Step config witnessState15 .wire witnessState16 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep16 : Execution.Step config witnessState16 .local witnessState17 := by
  exact Execution.Step.receive "NEW"

lemma witnessStep17 : Execution.Step config witnessState17 .route witnessState18 := by
  exact Execution.Step.route ⟨0, 2, 3221226240, 3221226243, 30, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep18 : Execution.Step config witnessState18 .filter witnessState19 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep19 : Execution.Step config witnessState19 .local witnessState20 := by
  exact Execution.Step.plain (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep20 : Execution.Step config witnessState20 .wire witnessState21 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep21 : Execution.Step config witnessState21 .local witnessState22 := by
  exact Execution.Step.receive "NEW"

lemma witnessStep22 : Execution.Step config witnessState22 .route witnessState23 := by
  exact Execution.Step.route ⟨5, 3, 3221226240, 3221226243, 30, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep23 : Execution.Step config witnessState23 .filter witnessState24 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep24 : Execution.Step config witnessState24 .local witnessState25 := by
  exact Execution.Step.plain (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep25 : Execution.Step config witnessState25 .wire witnessState26 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep26 : Execution.Step config witnessState26 .decrypt witnessState27 := by
  exact Execution.Step.decrypt ⟨200, 2, 3221225985, 3221226241, 168493057, 168493057, 169148417, 169148417, 0, none⟩ ⟨200, 2001, 3221225985, 3221226241⟩ ({ source := 168493057, destination := 169148417, protocol := "esp", ingress := "gray", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, ipv6NextHeader := 0, inboundPolicies := [], outboundPolicies := [], connectionState := "NEW" }) [⟨⟨1, 1001, 168493057, 169148417⟩, { source := 676660126683486899064358619217506861058, destination := 676660126762715061578622956811050811394, protocol := "ipv6-icmp", ingress := "red", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 0, ipv6NextHeader := 58, inboundPolicies := [], outboundPolicies := [], connectionState := "NEW" }⟩] "NEW" (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl rfl rfl rfl (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep27 : Execution.Step config witnessState27 .route witnessState28 := by
  exact Execution.Step.route ⟨19, 20, 169148416, 169148419, 30, 0, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep28 : Execution.Step config witnessState28 .filter witnessState29 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep29 : Execution.Step config witnessState29 .local witnessState30 := by
  exact Execution.Step.plain (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep30 : Execution.Step config witnessState30 .wire witnessState31 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep31 : Execution.Step config witnessState31 .decrypt witnessState32 := by
  exact Execution.Step.decrypt ⟨100, 1, 168493057, 169148417, 676660126683486899064358619217506861056, 676660126683486899082805363291216412671, 676660126762715061578622956811050811392, 676660126762715061597069700884760363007, 0, none⟩ ⟨100, 1001, 168493057, 169148417⟩ ({ source := 676660126683486899064358619217506861058, destination := 676660126762715061578622956811050811394, protocol := "ipv6-icmp", ingress := "red", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 0, ipv6NextHeader := 58, inboundPolicies := [], outboundPolicies := [], connectionState := "NEW" }) [] "NEW" (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl rfl rfl rfl (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep32 : Execution.Step config witnessState32 .route witnessState33 := by
  exact Execution.Step.route ⟨13, 15, 676660126762715061578622956811050811392, 676660126762715061597069700884760363007, 64, 256, 32766⟩ (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

lemma witnessStep33 : Execution.Step config witnessState33 .filter witnessState34 := by
  exact Execution.Step.filter (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep34 : Execution.Step config witnessState34 .local witnessState35 := by
  exact Execution.Step.plain (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep35 : Execution.Step config witnessState35 .wire witnessState36 := by
  exact Execution.Step.wire (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep36 : Execution.Step config witnessState36 .local witnessState37 := by
  exact Execution.Step.receive "NEW"

lemma witnessStep37 : Execution.Step config witnessState37 .local witnessState38 := by
  exact Execution.Step.«local» (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide)

lemma witnessStep38 : Execution.Step config witnessState38 .deliver witnessState39 := by
  exact Execution.Step.deliver 1 (by (try simp only [config, finiteConfig, SelectedRoute, Route.matches, accepts, StateBindsPolicy]); all_goals decide) rfl

tdn_data witnessActions : List Action from "../../data/evidence/FreshFamily644Witness.json" ["TDN.Imported.Family644.witnessActions"]

theorem positive_delivery_execution : (lts config).MTr witnessState0 witnessActions witnessState39 := by
  exact Cslib.LTS.MTr.stepL witnessStep0 (Cslib.LTS.MTr.stepL witnessStep1 (Cslib.LTS.MTr.stepL witnessStep2 (Cslib.LTS.MTr.stepL witnessStep3 (Cslib.LTS.MTr.stepL witnessStep4 (Cslib.LTS.MTr.stepL witnessStep5 (Cslib.LTS.MTr.stepL witnessStep6 (Cslib.LTS.MTr.stepL witnessStep7 (Cslib.LTS.MTr.stepL witnessStep8 (Cslib.LTS.MTr.stepL witnessStep9 (Cslib.LTS.MTr.stepL witnessStep10 (Cslib.LTS.MTr.stepL witnessStep11 (Cslib.LTS.MTr.stepL witnessStep12 (Cslib.LTS.MTr.stepL witnessStep13 (Cslib.LTS.MTr.stepL witnessStep14 (Cslib.LTS.MTr.stepL witnessStep15 (Cslib.LTS.MTr.stepL witnessStep16 (Cslib.LTS.MTr.stepL witnessStep17 (Cslib.LTS.MTr.stepL witnessStep18 (Cslib.LTS.MTr.stepL witnessStep19 (Cslib.LTS.MTr.stepL witnessStep20 (Cslib.LTS.MTr.stepL witnessStep21 (Cslib.LTS.MTr.stepL witnessStep22 (Cslib.LTS.MTr.stepL witnessStep23 (Cslib.LTS.MTr.stepL witnessStep24 (Cslib.LTS.MTr.stepL witnessStep25 (Cslib.LTS.MTr.stepL witnessStep26 (Cslib.LTS.MTr.stepL witnessStep27 (Cslib.LTS.MTr.stepL witnessStep28 (Cslib.LTS.MTr.stepL witnessStep29 (Cslib.LTS.MTr.stepL witnessStep30 (Cslib.LTS.MTr.stepL witnessStep31 (Cslib.LTS.MTr.stepL witnessStep32 (Cslib.LTS.MTr.stepL witnessStep33 (Cslib.LTS.MTr.stepL witnessStep34 (Cslib.LTS.MTr.stepL witnessStep35 (Cslib.LTS.MTr.stepL witnessStep36 (Cslib.LTS.MTr.stepL witnessStep37 (Cslib.LTS.MTr.stepL witnessStep38 Cslib.LTS.MTr.refl))))))))))))))))))))))))))))))))))))))

lemma witness_initial_stack : StackInvariant config layout witnessState0 := by
  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩

end TDN.Imported.Family644
