# Native cleanup janitor request phase

After a native bridge has recorded and validated its immutable physical
custody journal and trusted advisory receipt, it can request deletion
of the **two exact pinned encrypted detached EBS volumes** only after
fresh AWS evidence establishes the EC2 instance has terminated, the
resource tags and account match, no unexpected interfaces/instance role
exist, and both raw volumes are detached.

The function `request_detached_volume_deletion` makes only
`DeleteVolume` calls on the two journaled IDs. It makes no discovery
by wildcard or untrusted tags, and never creates a replacement. Failure,
timeout or ambiguous AWS response yields `JanitorUnknown`; some deletion
requests may already have succeeded and the full physical journal must
be retained for external reconciliation.

The action returns `DELETION_REQUESTED_PENDING_INDEPENDENT_INVENTORY`.
It deliberately **does not mark DISPOSED**. Two separated read-only
`DeletedInventory` records and a database transition are required
afterwards.

The call must run only with a narrowly scoped native AWS principal
that is forbidden from S3 witness/authority and customer-origin access,
and only after a durable deletion intent is persisted. This module
does not provision that principal, launch EC2, or perform real AWS tests.
