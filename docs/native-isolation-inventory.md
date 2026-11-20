# Native EC2 offline guest isolation inventory gate — SA-1.1 D6

Before allowing a disposable guest to run any untrusted submitted source,
the independent bridge must obtain a **fresh, complete, separately
credentialed** native AWS inventory.

`validate_offline_guest_inventory` demands pinned account/VPC/subnet/AZ/
security group IDs, VPC DNS disabled, no IPv6 associations, public IP/IPv6
address assignment/DNS64 disabled, no security-group ingress/egress, an
explicit effective subnet route table with only the VPC-local route,
and no internet/NAT gateways, VPC endpoints, peering, transit gateway
attachments or resolver forwarding.

Any missing, stale, ambiguous or unexpected field raises
`IsolationRejected`. Even with all checks passing, the only return
status is `LIVE_ISOLATION_DRILLS_REQUIRED`: control-plane descriptions,
security-group rules and VPC DNS settings do **not** prove actual guest
link-local reachability or IMDS isolation.

The bridge must separately verify that the guest has no instance profile,
IMDS disabled, no public/secondary NIC, no guest-accessible secrets,
and no reachable metadata, DNS, AWS endpoint or link-local route **from
inside an independently observed live guest**. Disposable encrypted raw
input/output devices, two-pass termination/DETACH proof, IAM trust
separation and exact AMI identity are separate mandatory gates.

**Not yet wired to a live AWS collector or launch scheduler.** The
current tests are deterministic inert inventories and show only the
expected fail-closed predicate. No EC2 instances are launched by CI.
Do not run hostile customer analysis or claim runtime isolation
solely because this module or CDK synthesis succeeds.
