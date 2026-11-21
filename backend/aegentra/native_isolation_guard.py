"""Read-only native AWS EC2 offline guest network admission candidate.

Passing these snapshot checks cannot certify isolation. Effective link-local
reachability, guest IMDS/DNS behavior, endpoint visibility, IAM reachability
and escape/bypass drills must be tested by independent security custodians.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


class IsolationRejected(ValueError):
    pass


@dataclass(frozen=True)
class GuestNetworkPin:
    account_id: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    availability_zone: str


@dataclass(frozen=True)
class NetworkInventory:
    """One complete and fresh control-plane inventory from read-only AWS APIs."""

    account_id: str
    vpc: dict[str, Any]
    subnet: dict[str, Any]
    security_group: dict[str, Any]
    effective_route_table: dict[str, Any]
    dns_support: bool
    dns_hostnames: bool
    internet_gateways: tuple[dict[str, Any], ...]
    nat_gateways: tuple[dict[str, Any], ...]
    vpc_endpoints: tuple[dict[str, Any], ...]
    peerings: tuple[dict[str, Any], ...]
    transit_gateways: tuple[dict[str, Any], ...]
    resolver_associations: tuple[dict[str, Any], ...]
    observed_at: datetime
    complete: bool


@dataclass(frozen=True)
class IsolationCandidate:
    vpc_id: str
    subnet_id: str
    security_group_id: str
    status: str = "LIVE_ISOLATION_DRILLS_REQUIRED"


def validate_offline_guest_inventory(
    *, pinned: GuestNetworkPin,
    inventory: NetworkInventory,
    now: datetime,
) -> IsolationCandidate:
    """Reject ambiguous cloud topology; never return a ready-to-run verdict."""
    if (
        not inventory.complete
        or now.tzinfo is None or inventory.observed_at.tzinfo is None
        or inventory.observed_at > now
        or now - inventory.observed_at > timedelta(seconds=30)
        or pinned.account_id != inventory.account_id
    ):
        raise IsolationRejected("offline topology is stale, partial or wrong account")

    vpc, subnet, sg, routes = (
        inventory.vpc, inventory.subnet,
        inventory.security_group, inventory.effective_route_table,
    )
    if (
        vpc.get("VpcId") != pinned.vpc_id
        or vpc.get("State") != "available"
        or vpc.get("Ipv6CidrBlockAssociationSet")
        or inventory.dns_support is not False
        or inventory.dns_hostnames is not False
        or subnet.get("SubnetId") != pinned.subnet_id
        or subnet.get("VpcId") != pinned.vpc_id
        or subnet.get("AvailabilityZone") != pinned.availability_zone
        or subnet.get("Ipv6CidrBlockAssociationSet")
        or subnet.get("MapPublicIpOnLaunch") is not False
        or subnet.get("AssignIpv6AddressOnCreation") is not False
        or subnet.get("EnableDns64") is not False
        or sg.get("GroupId") != pinned.security_group_id
        or sg.get("VpcId") != pinned.vpc_id
        or sg.get("IpPermissions") != []
        or sg.get("IpPermissionsEgress") != []
    ):
        raise IsolationRejected("offline network identity, DNS or security group drift")

    if routes.get("VpcId") != pinned.vpc_id:
        raise IsolationRejected("effective guest route table is untrusted")
    # Require explicit subnet association. Implicit main-table resolution
    # would need a separate complete association inventory to prove.
    associations = routes.get("Associations")
    if (
        not isinstance(associations, list)
        or sum(
            1 for a in associations
            if a.get("SubnetId") == pinned.subnet_id
            and a.get("AssociationState", {}).get("State") == "associated"
        ) != 1
    ):
        raise IsolationRejected("effective subnet-to-route association unproven")
    entries = routes.get("Routes")
    if not isinstance(entries, list) or len(entries) != 1:
        raise IsolationRejected("guest route table must have only one local route")
    only = entries[0]
    if (
        only.get("GatewayId") != "local"
        or only.get("DestinationCidrBlock") != vpc.get("CidrBlock")
        or only.get("State") != "active"
        or any(
            key in only for key in (
                "DestinationIpv6CidrBlock", "DestinationPrefixListId",
                "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
                "EgressOnlyInternetGatewayId", "NetworkInterfaceId",
            )
        )
    ):
        raise IsolationRejected("guest has an egress or nonlocal route")

    if any((
        inventory.internet_gateways,
        inventory.nat_gateways,
        inventory.vpc_endpoints,
        inventory.peerings,
        inventory.transit_gateways,
        inventory.resolver_associations,
    )):
        raise IsolationRejected("guest VPC exposes forbidden external connection")
    return IsolationCandidate(
        vpc_id=pinned.vpc_id,
        subnet_id=pinned.subnet_id,
        security_group_id=pinned.security_group_id,
    )
