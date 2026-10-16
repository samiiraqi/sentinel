# Sentinel Requirements

## Agents
- [x] Orchestrator agent that manages the specialist agents
- [x] Terraform agent
- [ ] App code agent
- [ ] Frontend agent
- [ ] Config / YAML agent
- [x] Secrets agent
- [x] Dependencies agent
- [ ] Availability agent
- [ ] WAF agent (checks WAF config in AWS/Azure code)
- [ ] CloudFront agent (checks CloudFront config)
- [ ] SAST agent (static source code scan)
- [ ] DAST agent (scans a running app; needs a design decision because it sends requests, which conflicts with the read-only rule)

## Approval
- [x] Human-in-the-loop approval for every action

## Backend
- [x] Backend API
- [x] Audit log of every decision

## Dashboard
- [x] View findings
- [x] Approve or reject actions

## Infrastructure as Code
- [ ] AWS (plan only, never apply)
- [ ] Azure (plan only, never apply)

## Automation
- [x] GitHub Actions workflows

## Security
- [ ] Security is the top priority in every component

## Containers
- [ ] Docker images: one for agents, one for backend, one for dashboard
- [ ] docker-compose.yml to run everything with one command
- [ ] Image scanning with Trivy and Hadolint
