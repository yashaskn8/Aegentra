import assert from "node:assert/strict";
import { test } from "node:test";
import { App, aws_ec2 as ec2 } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { WorkloadStack } from "../lib/workload-stack";
import { AnalysisStack } from "../lib/analysis-stack";
import { SecurityStack } from "../lib/security-stack";

function templateFor<T extends WorkloadStack | AnalysisStack | SecurityStack>(
  ctor: new (app: App, id: string) => T,
  id: string,
): Template {
  const app = new App();
  return Template.fromStack(new ctor(app, id));
}

test("isolated analysis skeleton has no public route or workload credential", () => {
  const template = templateFor(AnalysisStack, "AnalysisTest");
  template.resourceCountIs("AWS::EC2::InternetGateway", 0);
  template.resourceCountIs("AWS::EC2::NatGateway", 0);
  template.resourceCountIs("AWS::EC2::VPCEndpoint", 0);
  template.resourceCountIs("AWS::IAM::InstanceProfile", 0);
  // No idle or persistent guest should exist; the bridge owns ephemeral
  // launch only after a trusted per-attempt DB record exists.
  template.resourceCountIs("AWS::EC2::Instance", 0);
  template.resourceCountIs("AWS::EC2::Volume", 0);
  template.resourceCountIs("AWS::EC2::VPCPeeringConnection", 0);
});

test("workload database and evidence are private and encrypted", () => {
  const template = templateFor(WorkloadStack, "WorkloadTest");
  template.hasResourceProperties("AWS::RDS::DBInstance", {
    StorageEncrypted: true,
    PubliclyAccessible: false,
    DeletionProtection: true,
  });
  template.hasResourceProperties("AWS::S3::Bucket", {
    BucketEncryption: {},
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    },
    VersioningConfiguration: { Status: "Enabled" },
  });
  template.resourceCountIs("AWS::EC2::NatGateway", 0);
});

test("security archive has versioning and S3 object lock", () => {
  const template = templateFor(SecurityStack, "SecurityTest");
  template.hasResourceProperties("AWS::S3::Bucket", {
    ObjectLockEnabled: true,
    VersioningConfiguration: { Status: "Enabled" },
  });
  template.resourceCountIs("AWS::KMS::Key", 1);
});
