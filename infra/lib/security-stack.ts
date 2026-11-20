import {
  CfnOutput, RemovalPolicy, Stack, StackProps,
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

    // These signing keys are intentionally NOT granted to the workload,
    // API, release authority, or default EC2 principals. A separately
    // reviewed custodian must provision narrow, independent signer policies.
    const witnessSigningKey = new kms.Key(this, "WitnessSigningKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: RemovalPolicy.RETAIN,
      description: "Independent immutable witness certificate signing only",
    });
    const vetoSigningKey = new kms.Key(this, "SecurityVetoSigningKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: RemovalPolicy.RETAIN,
      description: "Independent live security-account veto signing only",
    });
    new CfnOutput(this, "WitnessSigningKeyArn", {
      value: witnessSigningKey.keyArn,
    });
    new CfnOutput(this, "SecurityVetoSigningKeyArn", {
      value: vetoSigningKey.keyArn,
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
