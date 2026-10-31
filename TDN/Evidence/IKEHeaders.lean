import TDN.Import.Command
import TDN.Evidence.EventTypes

namespace TDN.Imported.IKEHeaders

set_option maxRecDepth 100000

tdn_data pathMTU : Nat from "../../evidence/lean/IKEHeaders.json" ["TDN.Imported.IKEHeaders.pathMTU"]

tdn_data headers : List Evidence.IKEHeaderObservation from "../../evidence/lean/IKEHeaders.json" ["TDN.Imported.IKEHeaders.headers"]

theorem recorded_headers_fit_without_ip_fragmentation : Evidence.RecordedHeadersFitWithoutIPFragmentation headers pathMTU := by unfold Evidence.RecordedHeadersFitWithoutIPFragmentation headers pathMTU; decide

theorem recorded_exchange_message_kinds : Evidence.RecordedExchangeMessageKinds headers := by unfold Evidence.RecordedExchangeMessageKinds headers; decide

end TDN.Imported.IKEHeaders
