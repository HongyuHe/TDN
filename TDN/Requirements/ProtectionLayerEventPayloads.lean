import TDN.Requirements.ProtectionLayerEventTrace

namespace TDN.Requirements.Msc
open Compliance

lemma receive_event_has_trace_payload {payload observed : PayloadId} {start finish layers : List String}
    {earlier later : List NetworkEvent} {iface : String} {trafficClass : TrafficClass}
    (run : (protectionLayerSystem payload).MTr start
      (earlier ++ .receive observed iface layers trafficClass :: later) finish) : observed = payload := by
  obtain ⟨before, after, leading, step, trailing⟩ := event_trace_split _ run
  exact (protection_layer_receive_shape step).1

lemma transmit_event_has_trace_payload {payload observed : PayloadId} {start finish layers : List String}
    {earlier later : List NetworkEvent} {iface : String} {trafficClass : TrafficClass}
    (run : (protectionLayerSystem payload).MTr start
      (earlier ++ .transmit observed iface layers trafficClass :: later) finish) : observed = payload := by
  obtain ⟨before, after, leading, step, trailing⟩ := event_trace_split _ run
  exact (protection_layer_transmit_shape step).1

end TDN.Requirements.Msc
