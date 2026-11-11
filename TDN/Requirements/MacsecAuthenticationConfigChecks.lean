import TDN.Requirements.VerifiedMacsecAuthentication

namespace TDN.Requirements.Msc
open Compliance

instance (primitive : TLSPrimitive) (exchange : EAPExchange) : Decidable (exchange.Successful primitive) := by
  unfold EAPExchange.Successful Trust.MutuallyAdmits Trust.Admits
  infer_instance

instance (primitive : TLSPrimitive) (delivery : EAPBackendDelivery) : Decidable (delivery.Successful primitive) := by
  unfold EAPBackendDelivery.Successful
  infer_instance

instance (primitive : TLSPrimitive) (selected : MACsecAuthentication) (exchange : EAPExchange) :
    Decidable (EAPDeviceExchange primitive selected exchange) := by
  unfold EAPDeviceExchange
  infer_instance

instance (primitive : TLSPrimitive) (selected : MACsecAuthentication) (exchange : EAPExchange) :
    Decidable (EAPPeerExchange primitive selected exchange) := by
  unfold EAPPeerExchange
  infer_instance

instance (primitive : TLSPrimitive) (selected : MACsecAuthentication) (exchange : EAPExchange) :
    Decidable (EAPSelectedExchange primitive selected exchange) := by
  unfold EAPSelectedExchange
  infer_instance

instance (primitive : TLSPrimitive) (selected : MACsecAuthentication) (exchange : EAPExchange) :
    Decidable (EAPSessionBinding primitive selected exchange) := by
  unfold EAPSessionBinding
  infer_instance

instance {S A : Type} (record : MACsecSetupRecord) (model : ForwardingModel S A) :
    Decidable (record.InstallationChecked model) := by
  unfold MACsecSetupRecord.InstallationChecked
  infer_instance

instance {S A : Type} (record : MACsecSetupRecord) (model : ForwardingModel S A)
    (primitive : TLSPrimitive) (selected : MACsecAuthentication) : Decidable (record.EAPChecked model primitive selected) := by
  unfold MACsecSetupRecord.EAPChecked
  cases selected.exchanges[record.exchangeIndex]? <;> infer_instance

instance {S A : Type} (record : MACsecSetupRecord) (d : Deployment) (model : ForwardingModel S A)
    (primitive : TLSPrimitive) (authentication : List MACsecAuthentication) :
    Decidable (record.AuthenticationChecked d model primitive authentication) := by
  unfold MACsecSetupRecord.AuthenticationChecked
  cases authentication[record.authenticationIndex]? with
  | none => infer_instance
  | some selected =>
    cases d.tunnels[record.tunnelIndex]? with
    | none => infer_instance
    | some tunnel =>
      haveI : Decidable (match selected.method with
          | .preSharedCAK => record.installation.session = none
          | .eapTLS => record.EAPChecked model primitive selected) := by
        cases methodName : selected.method <;> infer_instance
      infer_instance

end TDN.Requirements.Msc
