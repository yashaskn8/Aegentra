# Read-only EC2/EBS deletion inventory

`disposal_collector.py` uses a separately enrolled read-only AWS role.
It queries the **exact** previously recorded EC2 instance and two EBS
volume IDs, never a tag-only discovery result. `InvalidVolume.NotFound`
for each pinned EBS ID and a terminated or explicitly missing EC2
instance are the only positive states. An EBS object still in `deleting`
is **not** complete. Unrecognized AWS errors, missing permissions, partial
pagination and ambiguous shapes fail closed.

Two separate successful inventory collections, at least 30 seconds apart,
must pass `verify_disposal` and be persisted with the physical attempt and
audit entry. No state transition deletes the immutable resource ID ledger.

This collector DOES NOT delete an EC2 resource, prove native guest
airgapping, or establish that a compromised IAM/API endpoint is honest.
Before production an independent security team must qualify live AWS
API behavior, IAM isolation, cleanup process and cost-leak alarms.

The CI suite exercises fakes only.
