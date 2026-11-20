import { App } from "aws-cdk-lib";
import { WorkloadStack } from "../lib/workload-stack";
import { AnalysisStack } from "../lib/analysis-stack";
import { SecurityStack } from "../lib/security-stack";

const app = new App();

// These are deliberately independent stacks: cross-account credentials,
// trust relationships and approved deployment identities are NOT invented.
new WorkloadStack(app, "AegentraWorkload");
new AnalysisStack(app, "AegentraAnalysis");
new SecurityStack(app, "AegentraSecurity");
