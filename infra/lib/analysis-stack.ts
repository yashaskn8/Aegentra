import {
  CfnOutput, Stack, StackProps,
  aws_ec2 as ec2,
} from "aws-cdk-lib";
import { Construct } from "constructs";

/**
 * Dedicated offline guest network. No persistent EC2 worker is deployed.
 *
 * Each attempt must be created by an independently authorized native bridge
 * only after persisting its exact AMI, instance, account, AZ, volume IDs,
 * generation and nonce. CDK synthesis cannot verify effective link-local
 * or AWS cross-account isolation and does not enable hostile input.
 */
export class AnalysisStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, "GuestVpc", {
      maxAzs: 2,
      natGateways: 0,
      enableDnsHostnames: false,
      enableDnsSupport: false,
      subnetConfiguration: [
        { name: "offline", subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
    });

    const group = new ec2.SecurityGroup(this, "OfflineGuestSecurityGroup", {
      vpc,
      allowAllOutbound: false,
      description: "No ingress or egress for disposable guest attempts",
    });

    new CfnOutput(this, "GuestSubnetId", {
      value: vpc.isolatedSubnets[0].subnetId,
      description: "Review route tables and link-local behavior before any use",
    });
    new CfnOutput(this, "GuestSecurityGroupId", {
      value: group.securityGroupId,
      description: "No egress here is necessary but not sufficient for isolation",
    });
  }
}
