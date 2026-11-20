# Independent security-account signing keys — undeployed CDK draft

The security-account CDK stack defines separate retained P-256 signing keys
for (1) immutable witness certificate signatures and (2) per-request
security-root STOP/veto signatures, in addition to the symmetric archive
encryption key. Asymmetric KMS key rotation and retention require a
separate documented custodian procedure; these keys do not enable automatic
rotation. No workload, API, or EC2 role is granted KMS `Sign`.

The separation exists at the **resource-definition** layer only. It does
not prove AWS organizational/account independence, ownership, enrolled
human custody, signed key rotation, KMS recovery, or safety of network
endpoints. Actual service roles, signer-key policies and the distribution
of independently pinned public keys must be reviewed and deployed by the
security account's administrators. No AWS deployment occurred.
