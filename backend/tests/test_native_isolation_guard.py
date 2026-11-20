"""Guest network candidate needs pinned native AWS topology + live drills."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from aegentra.native_isolation_guard import (
    GuestNetworkPin, IsolationRejected, NetworkInventory,
    validate_offline_guest_inventory,
)


def fixture():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    pin = GuestNetworkPin(
        account_id="123456789012", vpc_id="vpc-000000001",
        subnet_id="subnet-000000001", security_group_id="sg-000000001",
        availability_zone="us-east-1a",
    )
    vpc = {
        "VpcId": pin.vpc_id,
        "State": "available", "CidrBlock": "10.84.0.0/16",
        "Ipv6CidrBlockAssociationSet": [],
    }
    subnet = {
        "SubnetId": pin.subnet_id, "VpcId": pin.vpc_id,
        "AvailabilityZone": pin.availability_zone,
        "Ipv6CidrBlockAssociationSet": [],
        "MapPublicIpOnLaunch": False,
        "AssignIpv6AddressOnCreation": False,
        "EnableDns64": False,
    }
    sg = {
        "GroupId": pin.security_group_id, "VpcId": pin.vpc_id,
        "IpPermissions": [], "IpPermissionsEgress": [],
    }
    routes = {
        "VpcId": pin.vpc_id,
        "Associations": [{
            "SubnetId": pin.subnet_id,
            "AssociationState": {"State": "associated"},
        }],
        "Routes": [{
            "GatewayId": "local",
            "DestinationCidrBlock": vpc["CidrBlock"],
            "State": "active",
        }],
    }
    inv = NetworkInventory(
        account_id=pin.account_id,
        vpc=vpc, subnet=subnet, security_group=sg,
        effective_route_table=routes,
        dns_support=False, dns_hostnames=False,
        internet_gateways=(), nat_gateways=(),
        vpc_endpoints=(), peerings=(), transit_gateways=(),
        resolver_associations=(), observed_at=now, complete=True,
    )
    return pin, inv, now


def check(pin, inv, now):
    return validate_offline_guest_inventory(
        pinned=pin, inventory=inv, now=now,
    )


def test_only_closed_read_only_inventory_becomes_candidate_not_qualified():
    pin, inventory, now = fixture()
    candidate = check(pin, inventory, now)
    assert candidate.status == "LIVE_ISOLATION_DRILLS_REQUIRED"
    assert candidate.subnet_id == pin.subnet_id


@pytest.mark.parametrize("change", [
    "account", "stale", "future", "incomplete", "dns_support",
    "dns_names", "vpc_ipv6", "subnet_ipv6", "public_ip",
    "ipv6_auto", "dns64", "ingress", "egress",
    "endpoint", "nat", "internet", "peering", "transit",
    "resolver", "route", "multiple_routes", "implicit_main",
    "wrong_subnet", "wrong_az", "wrong_vpc",
])
def test_any_unverifiable_cloud_boundary_rejects_guest_candidate(change):
    pin, inv, now = fixture()
    if change == "account":
        inv = replace(inv, account_id="000000000000")
    elif change == "stale":
        inv = replace(inv, observed_at=now - timedelta(minutes=5))
    elif change == "future":
        inv = replace(inv, observed_at=now + timedelta(seconds=1))
    elif change == "incomplete":
        inv = replace(inv, complete=False)
    elif change == "dns_support":
        inv = replace(inv, dns_support=True)
    elif change == "dns_names":
        inv = replace(inv, dns_hostnames=True)
    elif change == "vpc_ipv6":
        inv.vpc["Ipv6CidrBlockAssociationSet"] = [{"Ipv6CidrBlock": "::/56"}]
    elif change == "subnet_ipv6":
        inv.subnet["Ipv6CidrBlockAssociationSet"] = [{"Ipv6CidrBlock": "::/64"}]
    elif change == "public_ip":
        inv.subnet["MapPublicIpOnLaunch"] = True
    elif change == "ipv6_auto":
        inv.subnet["AssignIpv6AddressOnCreation"] = True
    elif change == "dns64":
        inv.subnet["EnableDns64"] = True
    elif change == "ingress":
        inv.security_group["IpPermissions"] = [{"IpProtocol": "-1"}]
    elif change == "egress":
        inv.security_group["IpPermissionsEgress"] = [{"IpProtocol": "-1"}]
    elif change == "endpoint":
        inv = replace(inv, vpc_endpoints=({"VpcEndpointId": "vpce-1"},))
    elif change == "nat":
        inv = replace(inv, nat_gateways=({"NatGatewayId": "nat-1"},))
    elif change == "internet":
        inv = replace(inv, internet_gateways=({"InternetGatewayId": "igw-1"},))
    elif change == "peering":
        inv = replace(inv, peerings=({"VpcPeeringConnectionId": "pcx-1"},))
    elif change == "transit":
        inv = replace(inv, transit_gateways=({"TransitGatewayAttachmentId": "tgw-1"},))
    elif change == "resolver":
        inv = replace(inv, resolver_associations=({"ResolverRuleId": "rslvr-1"},))
    elif change == "route":
        inv.effective_route_table["Routes"][0]["GatewayId"] = "igw-1"
    elif change == "multiple_routes":
        inv.effective_route_table["Routes"].append({
            "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "nat-1",
            "State": "active",
        })
    elif change == "implicit_main":
        inv.effective_route_table["Associations"] = [{"Main": True}]
    elif change == "wrong_subnet":
        inv.subnet["SubnetId"] = "subnet-attacker"
    elif change == "wrong_az":
        inv.subnet["AvailabilityZone"] = "us-east-1b"
    else:
        inv.vpc["VpcId"] = "vpc-wrong"
    with pytest.raises(IsolationRejected):
        check(pin, inv, now)


def test_missing_required_control_plane_fields_fail_closed():
    pin, inv, now = fixture()
    inv.subnet.pop("EnableDns64")
    with pytest.raises(IsolationRejected):
        check(pin, inv, now)
