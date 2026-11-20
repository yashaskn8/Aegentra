import {
  RemovalPolicy, Stack, StackProps,
  aws_kms as kms,
  aws_s3 as s3,
} from "aws-cdk-lib";
import { Construct } from "constructs";

/**
 * Archive primitives only. Cross-account dual custody, independent witness,
 * lock retention terms and emergency veto still require explicit design.
 */
export class SecurityStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const archiveKey = new kms.Key(this, "ArchiveKey", {
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    new s3.Bucket(this, "AuditProofArchive", {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: archiveKey,
      versioned: true,
      objectLockEnabled: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
    });
  }
}
