# Sentinel Requirements

## Agents
- [ ] Orchestrator agent that manages the specialist agents
- [ ] Terraform agent
- [ ] App code agent
- [ ] Frontend agent
- [ ] Config / YAML agent
- [ ] Secrets agent
- [ ] Dependencies agent
- [ ] Availability agent

## Approval
- [ ] Human-in-the-loop approval for every action

## Backend
- [ ] Backend API
- [ ] Audit log of every decision

## Dashboard
- [ ] View findings
- [ ] Approve or reject actions

## Infrastructure as Code
- [ ] AWS (plan only, never apply)
- [ ] Azure (plan only, never apply)

## Automation
- [ ] GitHub Actions workflows

## Security
- [ ] Security is the top priority in every component

## Containers
- [ ] Docker images: one for agents, one for backend, one for dashboard
- [ ] docker-compose.yml to run everything with one command
- [ ] Image scanning with Trivy and Hadolint
