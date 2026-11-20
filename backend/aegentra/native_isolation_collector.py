"""Bounded native AWS read-only topology acquisition for offline guests.

The caller supplies preconfigured read-only EC2, STS and Route53Resolver
clients in the distinct analysis account. No EC2 create/launch/terminate
actions, no guest code execution, no network-exposed HTTP handler.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from aegentra.native_isolation_guard import (
    GuestNetworkPin, IsolationRejected, NetworkInventory,
    IsolationCandidate, validate_offline_guest_inventory,
)

MAX_PAGES = 20
MAX_ITEMS = 100


def _all_pages(
    client: Any, method: str, result_key: str, arguments: dict,
) -> tuple[dict, ...]:
    """Drain every returned NextToken; incomplete pagination fails closed."""
    seen: set[str] = set()
    token: str | None = None
    pages = 0
    items: list[dict] = []
    while True:
        pages += 1
        if pages > MAX_PAGES:
            raise IsolationRejected("cloud inventory exceeds page budget")
        kwargs = dict(arguments)
        if token is not None:
            kwargs["NextToken"] = token
        try:
            response = getattr(client, method)(**kwargs)
        except Exception as exc:
            raise IsolationRejected("native AWS inventory unavailable") from exc
        group = response.get(result_key)
        if not isinstance(group, list) or any(not isinstance(item, dict) for item in group):
            raise IsolationRejected("malformed native AWS inventory response")
        items.extend(group)
        if len(items) > MAX_ITEMS:
            raise IsolationRejected("cloud inventory exceeds item budget")
        token = response.get("NextToken")
        if token in (None, ""):
            return tuple(items)
        if not isinstance(token, str) or token in seen:
            raise IsolationRejected("ambiguous or repeated AWS pagination cursor")
        seen.add(token)


def _one(items: tuple[dict, ...], name: str) -> dict:
    if len(items) != 1:
        raise IsolationRejected("missing or ambiguous " + name)
    return items[0]


def collect_native_guest_inventory(
    *, ec2: Any, resolver: Any, sts: Any,
    pinned: GuestNetworkPin, now: datetime,
) -> NetworkInventory:
    """Use only read-only APIs; every unexamined connection fails acquisition."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise IsolationRejected("trusted UTC acquisition clock unavailable")
    try:
        account = sts.get_caller_identity()["Account"]
    except Exception as exc:
        raise IsolationRejected("cannot identify analysis AWS account") from exc
    if account != pinned.account_id:
        raise IsolationRejected("AWS inventory fetched in wrong account")

    vpc = _one(_all_pages(
        ec2, "describe_vpcs", "Vpcs", {"VpcIds": [pinned.vpc_id]}
    ), "pinned VPC")
    subnet = _one(_all_pages(
        ec2, "describe_subnets", "Subnets",
        {"SubnetIds": [pinned.subnet_id]}
    ), "pinned subnet")
    sg = _one(_all_pages(
        ec2, "describe_security_groups", "SecurityGroups",
        {"GroupIds": [pinned.security_group_id]}
    ), "pinned security group")

    associated = _all_pages(
        ec2, "describe_route_tables", "RouteTables",
        {"Filters": [
            {"Name": "association.subnet-id", "Values": [pinned.subnet_id]}
        ]},
    )
    route = _one(associated, "explicit effective route table")
    try:
        dns_support = ec2.describe_vpc_attribute(
            VpcId=pinned.vpc_id, Attribute="enableDnsSupport"
        )["EnableDnsSupport"]["Value"]
        dns_hostnames = ec2.describe_vpc_attribute(
            VpcId=pinned.vpc_id, Attribute="enableDnsHostnames"
        )["EnableDnsHostnames"]["Value"]
    except Exception as exc:
        raise IsolationRejected("cannot verify VPC DNS configuration") from exc
    if not isinstance(dns_support, bool) or not isinstance(dns_hostnames, bool):
        raise IsolationRejected("missing typed VPC DNS state")

    by_vpc = [{"Name": "vpc-id", "Values": [pinned.vpc_id]}]
    gateways = _all_pages(
        ec2, "describe_internet_gateways", "InternetGateways",
        {"Filters": [
            {"Name": "attachment.vpc-id", "Values": [pinned.vpc_id]}
        ]},
    )
    nat = _all_pages(
        ec2, "describe_nat_gateways", "NatGateways", {"Filter": by_vpc},
    )
    endpoints = _all_pages(
        ec2, "describe_vpc_endpoints", "VpcEndpoints", {"Filters": by_vpc},
    )
    peer_requester = _all_pages(
        ec2, "describe_vpc_peering_connections", "VpcPeeringConnections",
        {"Filters": [
            {"Name": "requester-vpc-info.vpc-id", "Values": [pinned.vpc_id]}
        ]},
    )
    peer_accepter = _all_pages(
        ec2, "describe_vpc_peering_connections", "VpcPeeringConnections",
        {"Filters": [
            {"Name": "accepter-vpc-info.vpc-id", "Values": [pinned.vpc_id]}
        ]},
    )
    transit = _all_pages(
        ec2, "describe_transit_gateway_vpc_attachments",
        "TransitGatewayVpcAttachments",
        {"Filters": [
            {"Name": "resource-id", "Values": [pinned.vpc_id]}
        ]},
    )
    resolver_associations = _all_pages(
        resolver, "list_resolver_rule_associations",
        "ResolverRuleAssociations",
        {"Filters": [{"Name": "VPCId", "Values": [pinned.vpc_id]}]},
    )

    return NetworkInventory(
        account_id=account, vpc=vpc, subnet=subnet, security_group=sg,
        effective_route_table=route, dns_support=dns_support,
        dns_hostnames=dns_hostnames,
        internet_gateways=gateways, nat_gateways=nat,
        vpc_endpoints=endpoints, peerings=peer_requester + peer_accepter,
        transit_gateways=transit,
        resolver_associations=resolver_associations,
        observed_at=now.astimezone(timezone.utc), complete=True,
    )


def evaluate_native_guest_network(
    *, ec2: Any, resolver: Any, sts: Any,
    pinned: GuestNetworkPin, now: datetime,
) -> IsolationCandidate:
    return validate_offline_guest_inventory(
        pinned=pinned,
        inventory=collect_native_guest_inventory(
            ec2=ec2, resolver=resolver, sts=sts, pinned=pinned, now=now,
        ),
        now=now,
    )
