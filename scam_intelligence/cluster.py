from typing import Iterable, List

from .schemas import AddressCluster, FlowEdge


class AddressClusterer:
    """
    Conservative address clustering.

    A cluster is based only on explicit observed flow relationships.
    It does not claim common ownership.
    """

    def cluster_from_flows(
        self,
        flows: Iterable[FlowEdge],
        seed: str,
    ) -> List[AddressCluster]:

        addresses = {seed.lower()}
        reasons = []

        for flow in flows:
            addresses.add(flow.source.lower())
            addresses.add(flow.target.lower())

            reasons.append(
                f"Observed transaction flow: "
                f"{flow.source} -> {flow.target}"
            )

        if len(addresses) <= 1:
            return []

        return [
            AddressCluster(
                cluster_id=f"FLOW-{seed.lower()[:12]}",
                addresses=sorted(addresses),
                reasons=reasons,
                confidence=0.50,
            )
        ]
