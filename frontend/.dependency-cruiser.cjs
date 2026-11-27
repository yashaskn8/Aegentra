const testPath = "(^e2e/|\\.(test|spec|pw)\\.[cm]?[jt]sx?$)";

module.exports = {
  forbidden: [
    { name: "no-circular-imports", severity: "error", from: {}, to: { circular: true } },
    { name: "no-unresolved-imports", severity: "error", from: {}, to: { couldNotResolve: true } },
    {
      name: "application-does-not-import-tests",
      severity: "error",
      from: { path: "^src/", pathNot: testPath },
      to: { path: testPath },
    },
    {
      name: "case-evidence-depends-on-no-workspace-or-operations-panel",
      severity: "error",
      from: { path: "^src/CaseEvidencePanel\\.tsx$" },
      to: { path: "^src/(main|App|AuthPanel|CasesPanel|OperationsPanel)\\.tsx$" },
    },
    {
      name: "operations-does-not-import-case-or-workspace-components",
      severity: "error",
      from: { path: "^src/OperationsPanel\\.tsx$" },
      to: { path: "^src/(main|App|AuthPanel|CasesPanel|CaseEvidencePanel)\\.tsx$" },
    },
  ],
  options: {
    doNotFollow: { path: "(^|/)node_modules/" },
    tsConfig: { fileName: "tsconfig.json" },
    tsPreCompilationDeps: true,
  },
};
