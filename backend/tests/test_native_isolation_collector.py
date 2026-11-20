"""Native AWS topology collector: bounded, complete, read-only acquisition."""
from datetime import datetime, timezone

import pytest

from aegentra.native_isolation_collector import (
    collect_native_guest_inventory, evaluate_native_guest_network,
)
from aegentra.native_isolation_guard import GuestNetworkPin, IsolationRejected


class FakeSTS:
    account = "123456789012"

    def get_caller_identity(self):
        return {"Account": self.account}


class FakeEC2:
    def __init__(self, pinned):
        vpc, subnet, sg = pinned.vpc_id, pinned.subnet_id, pinned.security_group_id
        self.calls = []
        self.dns = False
        self.responses = {
            "describe_vpcs": {"Vpcs": [{
                "VpcId": vpc, "State": "available", "CidrBlock": "10.4.0.0/16",
                "Ipv6CidrBlockAssociationSet": [],
            }]},
            "describe_subnets": {"Subnets": [{
                "SubnetId": subnet, "VpcId": vpc,
                "AvailabilityZone": pinned.availability_zone,
                "MapPublicIpOnLaunch": False,
                "AssignIpv6AddressOnCreation": False,
                "EnableDns64": False, "Ipv6CidrBlockAssociationSet": [],
            }]},
            "describe_security_groups": {"SecurityGroups": [{
                "GroupId": sg, "VpcId": vpc,
                "IpPermissions": [], "IpPermissionsEgress": [],
            }]},
            "describe_route_tables": {"RouteTables": [{
                "VpcId": vpc,
                "Associations": [{
                    "SubnetId": subnet,
                    "AssociationState": {"State": "associated"},
                }],
                "Routes": [{
                    "DestinationCidrBlock": "10.4.0.0/16",
                    "GatewayId": "local", "State": "active",
                }],
            }]},
            "describe_internet_gateways": {"InternetGateways": []},
            "describe_nat_gateways": {"NatGateways": []},
            "describe_vpc_endpoints": {"VpcEndpoints": []},
            "describe_vpc_peering_connections": {"VpcPeeringConnections": []},
            "describe_transit_gateway_vpc_attachments": {
                "TransitGatewayVpcAttachments": [],
            },
        }

    def __getattr__(self, name):
        if name not in self.responses:
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            return self.responses[name]
        return call

    def describe_vpc_attribute(self, *, VpcId, Attribute):
        self.calls.append(("describe_vpc_attribute", {"Attribute": Attribute}))
        return {
            "EnableDnsSupport" if Attribute == "enableDnsSupport"
            else "EnableDnsHostnames": {"Value": self.dns},
        }


class FakeResolver:
    def list_resolver_rule_associations(self, **kwargs):
        return {"ResolverRuleAssociations": []}


def fixture():
    pin = GuestNetworkPin(
        account_id="123456789012", vpc_id="vpc-test",
        subnet_id="subnet-test", security_group_id="sg-test",
        availability_zone="us-east-1a",
    )
    return pin, FakeEC2(pin), FakeResolver(), FakeSTS(), datetime.now(timezone.utc)


def test_full_native_read_only_collector_returns_drill_candidate():
    pin, ec2, resolver, sts, now = fixture()
    inventory = collect_native_guest_inventory(
        ec2=ec2, resolver=resolver, sts=sts, pinned=pin, now=now,
    )
    assert inventory.complete
    assert inventory.vpc["VpcId"] == pin.vpc_id
    assert inventory.account_id == pin.account_id
    assert evaluate_native_guest_network(
        ec2=ec2, resolver=resolver, sts=sts, pinned=pin, now=now,
    ).status == "LIVE_ISOLATION_DRILLS_REQUIRED"
    assert all(
        name.startswith("describe_") for name, _ in ec2.calls
    )


def test_wrong_account_refuses_to_query_cloud_resources():
    pin, ec2, resolver, sts, now = fixture()
    sts.account = "000000000000"
    with pytest.raises(IsolationRejected, match="wrong account"):
        evaluate_native_guest_network(
            ec2=ec2, resolver=resolver, sts=sts, pinned=pin, now=now,
        )
    assert not ec2.calls


@pytest.mark.parametrize("bad", [
    "external_endpoint", "malformed", "repeated_cursor", "dns",
])
def test_untrusted_cloud_inventory_never_produces_candidate(bad):
    pin, ec2, resolver, sts, now = fixture()
    if bad == "external_endpoint":
        ec2.responses["describe_vpc_endpoints"]["VpcEndpoints"] = [{
            "VpcEndpointId": "vpce-unexpected"
        }]
    elif bad == "malformed":
        ec2.responses["describe_nat_gateways"].pop("NatGateways")
    elif bad == "repeated_cursor":
        ec2.responses["describe_vpcs"]["NextToken"] = "still-more"
    else:
        ec2.dns = True
    with pytest.raises(IsolationRejected):
        evaluate_native_guest_network(
            ec2=ec2, resolver=resolver, sts=sts, pinned=pin, now=now,
        )


def test_unavailable_resolver_inventory_is_fail_closed():
    pin, ec2, resolver, sts, now = fixture()
    with pytest.raises(IsolationRejected):
        collect_native_guest_inventory(
            ec2=ec2, resolver=object(), sts=sts, pinned=pin, now=now,
        )
