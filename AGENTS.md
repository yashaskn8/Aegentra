# Aegentra engineering rules

Inspired by the small-diff, first-principles coding discipline often associated with Andrej Karpathy; these are our own project rules, not an official published standard.

- Read the relevant architecture section before changing security behavior.
- Make the smallest coherent, testable change. Prefer a few explicit functions over a framework.
- Understand the existing code before editing; preserve contracts and avoid speculative abstractions.
- State assumptions. Fail closed on missing evidence; never confuse an anomaly score with an authorization decision.
- Write tests for the intended behavior, failure behavior, and adversarial edge cases.
- Keep code and comments straightforward: explain why when it is not obvious, not what each line does.
- Never invent test results, leave fake security controls, or silently deploy.
- No Docker, Kubernetes, runtime evaluation of submitted code, or AWS mutations without explicit authorization.
- Work directly on main, as requested by the repository owner. Keep each commit small and independently reviewable; verify GitHub Actions before reporting success. Do not deploy without explicit authorization.
