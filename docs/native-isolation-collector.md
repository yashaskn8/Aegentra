# Read-only native AWS guest-network collector — SA-1.1 D6

`native_isolation_collector.py` accepts pre-configured, independently
credentialed boto3 EC2/STS/Route53Resolver clients in the analysis account.
It fetches the pinned VPC, subnet, security group, **explicit** subnet
route table and VPC DNS attributes; then exhaustively checks internet
gateways, NAT gateways, VPC endpoints, both peering directions,
transit gateway attachments and resolver-rule associations.

All pagination uses bounded `NextToken` iteration. Missing collection,
unknown cursor, repeated token, oversized inventory, denied AWS API or
wrong STS account fails closed. No EC2 launch/attach/detach or mutation
operations occur. The collector passes a complete control-plane snapshot
to the separate `validate_offline_guest_inventory` predicate.

The only positive outcome is
`LIVE_ISOLATION_DRILLS_REQUIRED`, **not** "safe guest" or permission
to analyze hostile uploaded code. Production qualification additionally
requires a separate, limited IAM account, independent signed AMI and
guest/bridge administrators, no instance profile or IMDS, no IPv6,
live link-local and egress probes, raw device confinement, two-pass
detachment and failed-job janitor tests. CDK synthesis is no evidence
for those runtime claims.

These tests are fake *read-only response* fixtures. They establish
API contract parsing, account pins and fail-closed controls, not
live AWS reachability. No AWS resources were deployed.
