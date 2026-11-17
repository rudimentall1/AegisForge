from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, Iterable, List, Tuple

from .schemas import Transaction


@dataclass
class EntityLink:
    source: str
    target: str
    relation_type: str
    strength: float
    evidence_ids: List[str] = field(default_factory=list)
    tx_hashes: List[str] = field(default_factory=list)
    reason: str = ""


class EntityLinker:

    DIRECT_TRANSFER = "DIRECT_TRANSFER"
    COMMON_FUNDER = "COMMON_FUNDER"
    COMMON_DESTINATION = "COMMON_DESTINATION"
    REPEATED_COUNTERPARTY = "REPEATED_COUNTERPARTY"

    # Correlation links are deliberately capped.
    MAX_COMMON_COUNTERPARTIES = 8

    # A single mass-funder/destination should not dominate
    # the entity graph.
    MAX_CORRELATION_LINKS_PER_ENTITY = 20

    def link(
        self,
        transactions: Iterable[Transaction],
        seed: str = "",
    ) -> List[EntityLink]:

        transactions = [
            tx
            for tx in transactions
            if tx.tx_hash
            and tx.from_address
            and tx.to_address
        ]

        pair_transactions: Dict[
            Tuple[str, str],
            List[str],
        ] = {}

        outgoing: Dict[
            str,
            Dict[str, List[str]],
        ] = {}

        incoming: Dict[
            str,
            Dict[str, List[str]],
        ] = {}

        for tx in transactions:
            source = tx.from_address.lower()
            target = tx.to_address.lower()

            if not source or not target or source == target:
                continue

            pair_transactions.setdefault(
                (source, target),
                [],
            ).append(tx.tx_hash)

            outgoing.setdefault(
                source,
                {},
            ).setdefault(
                target,
                [],
            ).append(tx.tx_hash)

            incoming.setdefault(
                target,
                {},
            ).setdefault(
                source,
                [],
            ).append(tx.tx_hash)

        links: Dict[
            Tuple[str, str, str],
            EntityLink,
        ] = {}

        self._add_direct_transfers(
            pair_transactions,
            links,
        )

        self._add_repeated_counterparties(
            pair_transactions,
            links,
        )

        self._add_common_funders(
            outgoing,
            links,
        )

        self._add_common_destinations(
            incoming,
            links,
        )

        return sorted(
            links.values(),
            key=lambda link: (
                -link.strength,
                link.relation_type,
                link.source,
                link.target,
            ),
        )

    # ------------------------------------------------------------------
    # DIRECT TRANSFER
    # ------------------------------------------------------------------

    def _add_direct_transfers(
        self,
        pair_transactions: Dict[Tuple[str, str], List[str]],
        links: Dict[Tuple[str, str, str], EntityLink],
    ) -> None:

        for (source, target), tx_hashes in pair_transactions.items():

            key = (
                source,
                target,
                self.DIRECT_TRANSFER,
            )

            links[key] = EntityLink(
                source=source,
                target=target,
                relation_type=self.DIRECT_TRANSFER,
                strength=0.70,
                evidence_ids=[
                    f"TX:{tx_hash}"
                    for tx_hash in tx_hashes
                ],
                tx_hashes=list(tx_hashes),
                reason=(
                    "Observed direct on-chain "
                    "transfer between the addresses"
                ),
            )

    # ------------------------------------------------------------------
    # REPEATED COUNTERPARTY
    # ------------------------------------------------------------------

    def _add_repeated_counterparties(
        self,
        pair_transactions: Dict[Tuple[str, str], List[str]],
        links: Dict[Tuple[str, str, str], EntityLink],
    ) -> None:

        for (source, target), tx_hashes in pair_transactions.items():

            count = len(tx_hashes)

            if count < 2:
                continue

            # Repetition increases confidence, but never turns
            # correlation into ownership attribution.
            strength = min(
                0.85,
                0.50 + 0.07 * min(count, 5),
            )

            key = (
                source,
                target,
                self.REPEATED_COUNTERPARTY,
            )

            links[key] = EntityLink(
                source=source,
                target=target,
                relation_type=self.REPEATED_COUNTERPARTY,
                strength=round(strength, 4),
                evidence_ids=[
                    f"TX:{tx_hash}"
                    for tx_hash in tx_hashes
                ],
                tx_hashes=list(tx_hashes),
                reason=(
                    f"Observed {count} transfers "
                    "between the same address pair"
                ),
            )

    # ------------------------------------------------------------------
    # COMMON FUNDER
    # ------------------------------------------------------------------

    def _add_common_funders(
        self,
        outgoing: Dict[str, Dict[str, List[str]]],
        links: Dict[Tuple[str, str, str], EntityLink],
    ) -> None:

        for funder, recipients in outgoing.items():

            # Mass-funding addresses create combinatorial noise.
            if len(recipients) < 2:
                continue

            if len(recipients) > self.MAX_COMMON_COUNTERPARTIES:
                continue

            pairs = list(combinations(
                recipients.keys(),
                2,
            ))

            if len(pairs) > self.MAX_CORRELATION_LINKS_PER_ENTITY:
                pairs = pairs[
                    :self.MAX_CORRELATION_LINKS_PER_ENTITY
                ]

            for left, right in pairs:

                tx_hashes = (
                    recipients[left]
                    + recipients[right]
                )

                key = (
                    left,
                    right,
                    self.COMMON_FUNDER,
                )

                links[key] = EntityLink(
                    source=left,
                    target=right,
                    relation_type=self.COMMON_FUNDER,
                    strength=0.35,
                    evidence_ids=[
                        f"TX:{tx_hash}"
                        for tx_hash in tx_hashes
                    ],
                    tx_hashes=list(tx_hashes),
                    reason=(
                        "Both addresses received funds "
                        f"from common source {funder}"
                    ),
                )

    # ------------------------------------------------------------------
    # COMMON DESTINATION
    # ------------------------------------------------------------------

    def _add_common_destinations(
        self,
        incoming: Dict[str, Dict[str, List[str]]],
        links: Dict[Tuple[str, str, str], EntityLink],
    ) -> None:

        for destination, senders in incoming.items():

            if len(senders) < 2:
                continue

            # Avoid graph explosion around exchanges,
            # routers and other high-degree destinations.
            if len(senders) > self.MAX_COMMON_COUNTERPARTIES:
                continue

            pairs = list(combinations(
                senders.keys(),
                2,
            ))

            if len(pairs) > self.MAX_CORRELATION_LINKS_PER_ENTITY:
                pairs = pairs[
                    :self.MAX_CORRELATION_LINKS_PER_ENTITY
                ]

            for left, right in pairs:

                tx_hashes = (
                    senders[left]
                    + senders[right]
                )

                key = (
                    left,
                    right,
                    self.COMMON_DESTINATION,
                )

                links[key] = EntityLink(
                    source=left,
                    target=right,
                    relation_type=self.COMMON_DESTINATION,
                    strength=0.30,
                    evidence_ids=[
                        f"TX:{tx_hash}"
                        for tx_hash in tx_hashes
                    ],
                    tx_hashes=list(tx_hashes),
                    reason=(
                        "Both addresses sent funds "
                        f"to common destination {destination}"
                    ),
                )
