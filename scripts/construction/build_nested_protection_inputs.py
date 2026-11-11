"""Build source-bound RG007 flow and public authentication records."""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "data/evidence/nestedProtection/exports"
DEST = ROOT / "data/evidence/nestedProtection"

def read(path):
    return json.loads(path.read_text())

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def stamp(policy, association):
    return dict(tag=policy["tag"], association=association["spi"],
        sender=association["sender"], receiver=association["receiver"])

def build(profile, collection):
    cohort_path = ROOT / f"data/evidence/continuation/MtuSizing_{profile}.json"
    authentication_path = INPUTS / f"{collection}-authentication-services-native_authentication_services.json"
    cohort = read(cohort_path)
    authentication = read(authentication_path)
    records = cohort["records"]
    names = records["ownerNames"]
    contexts = []
    uses = []
    def installation(owner, policy):
        return next(row["installation"]["association"] for row in cohort["installations"]
            if row["installation"]["device"] == owner
            and row["installation"]["direction"] == "outbound"
            and row["installation"]["association"]["reqid"] == policy["id"]
            and row["installation"]["association"]["sender"] == policy["sender"]
            and row["installation"]["association"]["receiver"] == policy["receiver"])
    for source in cohort["sourceEntries"]:
        network = next(row for row in cohort["networks"] if row["id"] == source["network"])
        inner = next(row for row in records["tunnels"]
            if row["layer"] == "inner" and row["sender"] in network["innerComponents"])
        destination = next(row for row in cohort["networks"] if inner["receiver"] in row["innerComponents"])
        destination_entry = next(row for row in cohort["sourceEntries"] if row["network"] == destination["id"])
        source_owner = names.index(inner["sender"])
        policy = next(row for row in records["nativeDevices"][source_owner]["egressPolicies"] if row["tag"] == 1)
        inner_sa = installation(source_owner, policy)
        possible = []
        for owner, device in enumerate(records["nativeDevices"]):
            for outer_policy in device["egressPolicies"]:
                if outer_policy["tag"] == 2 and outer_policy["sourceLow"] <= inner_sa["sender"] <= outer_policy["sourceHigh"] and outer_policy["destinationLow"] <= inner_sa["receiver"] <= outer_policy["destinationHigh"]:
                    outer = next(row for row in records["tunnels"] if row["layer"] == "outer" and row["sender"] == names[owner])
                    possible.append((owner, outer_policy, outer))
        assert len(possible) == 1
        outer_owner, outer_policy, outer = possible[0]
        contexts.append(dict(flow=dict(sourceNetwork=network["id"], destinationNetwork=destination["id"],
                innerTunnel=inner["id"], outerTunnel=outer["id"]),
            originDomain=source["originDomain"], sourceInnerOwner=source_owner,
            sourceHostOwner=records["nativeIfaces"][source["hostIface"]]["owner"],
            destinationInnerOwner=names.index(inner["receiver"]),
            destinationHostOwner=records["nativeIfaces"][destination_entry["hostIface"]]["owner"],
            innerStamp=stamp(policy, inner_sa), outerStamp=stamp(outer_policy, installation(outer_owner, outer_policy)),
            remoteLow=policy["destinationLow"], remoteHigh=policy["destinationHigh"]))
        uses.append([inner["sender"], outer["sender"]])
    bindings = []
    for row in authentication["authentication_services"]:
        assert row["certificateAuthenticated"] is True
        assert row["preSharedCAKAuthenticated"] is False
        bindings.append(dict(device=row["device"], authorityId=row["authorityId"],
            certificateAuthenticated=row["certificateAuthenticated"], preSharedCAKAuthenticated=row["preSharedCAKAuthenticated"],
            localAuth=row["localAuth"], remoteAuth=row["remoteAuth"], epoch=row["epoch"], phase=row["phase"],
            ikeUniqueId=row["ikeUniqueId"], childUniqueId=row["childUniqueId"], peerDevice=row["peerDevice"],
            configObservation=row["configObservation"], saObservation=row["saObservation"],
            authenticationLogObservation=row["authenticationLogObservation"], authenticationSAObservation=row["authenticationSAObservation"],
            caObservation=row["caObservation"], leafObservation=row["leafObservation"],
            loadedCertificatesObservation=row["loadedCertificatesObservation"], loadedConnectionObservation=row["loadedConnectionObservation"],
            certificateDirectory=row["certificateDirectory"], certificateFile=row["certificateFile"],
            trustDirectory=row["trustDirectory"], trustFile=row["trustFile"],
            publicIssuerSignaturesChecked=row["publicIssuerSignaturesChecked"], authoritySha256=row["authority"]["sha256"],
            authorityIsCA=row["authority"]["basicConstraints"]["ca"], authorityKeyCertSign=row["authority"]["keyCertSign"],
            authorityDer=copy.deepcopy(row["authority"]["der"]), localCertificateDer=copy.deepcopy(row["localCertificate"]["der"]),
            peerCertificateDer=copy.deepcopy(row["peerCertificate"]["der"])))
    result=dict(contexts=contexts, authenticationBindings=bindings, innerOuterUses=uses,
        authenticationRaw=authentication,
        provenance=dict(cohort=str(cohort_path.relative_to(ROOT)), cohortSha256=sha256(cohort_path),
            authentication=str(authentication_path.relative_to(ROOT)), authenticationSha256=sha256(authentication_path),
            interpretation="Fixed recorded session; logical CA relationships; no running CA, current validity or approval claim."))
    DEST.mkdir(parents=True, exist_ok=True)
    output=DEST / f"{profile}IPsec.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return dict(path=str(output.relative_to(ROOT)), sha256=sha256(output), contexts=len(contexts), authenticationBindings=len(bindings))

if __name__ == "__main__":
    print(json.dumps([build("Baseline", "v31r-baseline-red-cohort"), build("Shared", "v31r-shared-sizing-cohort")], indent=2))
