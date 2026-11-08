import TDN.Semantics.PacketSource

namespace TDN.PacketSource

structure EmissionConditions (processing : Processing) : Prop where
  template : ∀ request datagrams, processing.process request = .emitted datagrams →
    request.TemplateValid
  mtu : ∀ request datagrams, processing.process request = .emitted datagrams →
    request.MtuOverhead < processing.sourceMtu request.iface
  nonempty : ∀ request datagrams, processing.process request = .emitted datagrams → datagrams ≠ []
  application : ∀ request datagrams, processing.process request = .emitted datagrams →
    (datagrams.map Datagram.application).flatten = request.application
  decoded : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, datagram.Decoded
  headers : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, datagram.HeaderFrom request
  fragments : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, datagram.Reassembles (processing.sourceMtu request.iface)
  protocolSize : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, datagram.Raw.length ≤ request.ProtocolLimit
  streamSize : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, request.mode = .stream →
      datagram.Raw.length ≤ processing.sourceMtu request.iface
  datagramMode : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ dontFragment, request.mode = .datagram dontFragment → datagrams.length = 1
  dfSize : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, request.mode = .datagram true →
      datagram.MtuBytes ≤ processing.sourceMtu request.iface
  dfHeader : ∀ request datagrams, processing.process request = .emitted datagrams →
    ∀ datagram ∈ datagrams, ∀ dontFragment, request.mode = .datagram dontFragment →
      match datagram.body with
      | .datagram packet => packet.source < 2^32 →
          (field datagram.networkHeader 6 2 / 16384 % 2 = 1 ↔ dontFragment = true)
      | _ => True

structure ErrorConditions (processing : Processing) : Prop where
  unsupported : ∀ request, processing.process request = .error .unsupportedTemplate →
    ¬ request.TemplateValid
  invalidMtu : ∀ request, processing.process request = .error .invalidMtu →
    request.TemplateValid ∧ processing.sourceMtu request.iface ≤ request.MtuOverhead
  protocolLength : ∀ request, processing.process request = .error .protocolLength →
    request.TemplateValid ∧ (∃ dontFragment, request.mode = .datagram dontFragment) ∧
      request.ProtocolLimit < request.PacketSize
  mtuExceeded : ∀ request, processing.process request = .error .mtuExceeded →
    request.TemplateValid ∧
      (request.mode = .datagram true ∨ ∃ header, request.body = .ethernet header) ∧
      processing.sourceMtu request.iface < request.MtuBytes ∧
      request.PacketSize ≤ request.ProtocolLimit

lemma emitted_datagram_valid {processing : Processing} (conditions : EmissionConditions processing)
    {request : Request} {datagrams : List Datagram}
    (emitted : processing.process request = .emitted datagrams)
    {datagram : Datagram} (member : datagram ∈ datagrams) :
    datagram.ValidFor request (processing.sourceMtu request.iface) := by
  refine ⟨conditions.decoded request datagrams emitted datagram member,
    conditions.headers request datagrams emitted datagram member,
    conditions.fragments request datagrams emitted datagram member,
    conditions.protocolSize request datagrams emitted datagram member,
    conditions.streamSize request datagrams emitted datagram member, ?_⟩
  intro dontFragment mode
  refine ⟨?_, conditions.dfHeader request datagrams emitted datagram member dontFragment mode⟩
  intro df
  subst dontFragment
  exact conditions.dfSize request datagrams emitted datagram member mode

theorem processing_outcomes_valid (processing : Processing)
    (emissions : EmissionConditions processing) (errors : ErrorConditions processing)
    (request : Request) :
    (processing.process request).Valid request (processing.sourceMtu request.iface) := by
  cases outcome : processing.process request with
  | emitted datagrams =>
    exact ⟨emissions.template request datagrams outcome, emissions.mtu request datagrams outcome,
      emissions.nonempty request datagrams outcome,
      emissions.application request datagrams outcome,
      fun datagram member => emitted_datagram_valid emissions outcome member,
      emissions.datagramMode request datagrams outcome⟩
  | error reason =>
    cases reason with
    | unsupportedTemplate => exact errors.unsupported request outcome
    | invalidMtu => exact errors.invalidMtu request outcome
    | protocolLength => exact errors.protocolLength request outcome
    | mtuExceeded => exact errors.mtuExceeded request outcome

end TDN.PacketSource
