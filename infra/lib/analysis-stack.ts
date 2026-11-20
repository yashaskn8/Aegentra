import {
  CfnParameter, Stack, StackProps,
  aws_ec2 as ec2,
} from "aws-cdk-lib";
import { Construct } from "constructs";

/**
 * A deliberately disconnected EC2 skeleton. It is NOT yet an approved
 * untrusted-input sandbox: AMI, kernel hardening and negative reachability
 * testing are prerequisites to accepting customer bytes.
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

    const guestSecurityGroup = new ec2.SecurityGroup(this, "GuestSecurityGroup", {
      vpc,
      allowAllOutbound: false,
      description: "Offline analysis guest: no ingress or egress",
    });

    const imageId = new CfnParameter(this, "QualifiedNativeAmiId", {
      type: "String",
      description: "Independently reviewed, signed native Linux AMI (must be qualified)",
      allowedPattern: "^ami-[0-9a-fA-F]+$",
    });

    new ec2.CfnInstance(this, "InertGuestPrototype", {
      imageId: imageId.valueAsString,
      instanceType: "t3.small",
      metadataOptions: {
        httpEndpoint: "disabled",
        httpTokens: "required",
        instanceMetadataTags: "disabled",
      },
      networkInterfaces: [{
        deviceIndex: "0",
        subnetId: vpc.isolatedSubnets[0].subnetId,
        groupSet: [guestSecurityGroup.securityGroupId],
        associatePublicIpAddress: false,
      }],
      // No instance profile, user data, endpoints, NAT or internet gateway.
    });
  }
}
