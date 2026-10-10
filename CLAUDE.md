# Sentinel – Hard Rules

These rules are non-negotiable. Security is the top priority.

- NEVER run `terraform apply` or `terraform destroy`. Only `terraform fmt`, `terraform validate`, and `terraform plan` are allowed.
- NEVER put real secrets or API keys in the repo. Use `.env` (git-ignored) locally; `.env.example` holds empty placeholders only.
- Agents are READ-ONLY. They never change files or infrastructure.
- Every action requires explicit human approval.
- Every decision is written to an audit log.
- Keep each step small. Explain what you did in short, plain English.
