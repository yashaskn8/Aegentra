import {
  Duration, RemovalPolicy, Stack, StackProps,
  aws_ec2 as ec2,
  aws_kms as kms,
  aws_rds as rds,
  aws_s3 as s3,
  aws_sqs as sqs,
} from "aws-cdk-lib";
import { Construct } from "constructs";

/** Native, closed-network pilot data foundation. No workload is deployed yet. */
export class WorkloadStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, "WorkloadVpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: "database", subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
    });

    const evidenceKey = new kms.Key(this, "EvidenceKey", {
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    new s3.Bucket(this, "EvidenceBucket", {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: evidenceKey,
      versioned: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      publicReadAccess: false,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const dlq = new sqs.Queue(this, "ScanDeadLetterQueue", {
      encryption: sqs.QueueEncryption.KMS_MANAGED,
      retentionPeriod: Duration.days(14),
    });

    new sqs.Queue(this, "ScanQueue", {
      encryption: sqs.QueueEncryption.KMS_MANAGED,
      visibilityTimeout: Duration.minutes(10),
      deadLetterQueue: { queue: dlq, maxReceiveCount: 5 },
    });

    new rds.DatabaseInstance(this, "StateDatabase", {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_16,
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MEDIUM),
      credentials: rds.Credentials.fromGeneratedSecret("aegentra_admin"),
      databaseName: "aegentra",
      publiclyAccessible: false,
      storageEncrypted: true,
      allocatedStorage: 30,
      backupRetention: Duration.days(7),
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
      multiAz: false, // Pilot only. Production HA requires a reviewed separate profile.
    });
  }
}
