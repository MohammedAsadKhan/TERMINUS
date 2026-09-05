# Terminus Application Overview

## Application Description

Terminus is an AI-assisted Security Operations Center (SOC) application that helps organizations investigate and manage cybersecurity alerts. The application receives security alerts from a Security Information and Event Management (SIEM) platform such as Wazuh, validates and prioritizes each alert through a deterministic policy engine, and gathers relevant forensic evidence. An AI investigation component then produces a structured assessment containing the incident's severity, confidence level, summary, and recommended response actions. The results are stored as incident tickets and presented to authorized users through an analyst dashboard.

The application is intended to reduce alert overload and make initial incident investigation faster and more consistent, particularly for organizations that cannot operate a large, around-the-clock SOC. Terminus supports multiple organizations with separated data, role-based access, configurable notification and ticketing integrations, and interchangeable AI and SIEM providers. Human analysts remain responsible for reviewing important findings and approving security actions that could affect systems or users.

## Application Customers / Users

### Customers

1. **Small and mid-sized organizations:** These organizations may use a SIEM but lack enough security personnel to investigate every alert continuously. Terminus gives them a centralized tool for prioritizing alerts, creating incident records, and notifying the appropriate staff.
2. **Managed Security Service Providers (MSSPs):** MSSPs monitor security events for several client organizations. Terminus's multi-tenant design allows an MSSP to keep each customer's users, alerts, incidents, and configuration separated within one application.
3. **Educational institutions and cybersecurity training programs:** Schools and training labs can use the application's offline simulation capability and sample alerts to demonstrate SOC workflows without depending on a production network.

### Users

1. **Security analysts and incident responders:** These users review alerts, examine collected evidence, assess AI-generated findings, manage incident tickets, and document response decisions.
2. **Organization and security administrators:** Administrators configure an organization's users, roles, integrations, notification channels, and access permissions. They are also responsible for approving higher-impact response actions.
3. **IT staff:** IT personnel receive actionable incident information and use it to investigate affected hosts, accounts, or services and perform approved remediation work.
4. **Managers and auditors:** Read-only users review incident history, severity summaries, response status, and reports for oversight, compliance, and planning purposes.

Customers are the organizations that deploy or obtain the application, while users are the people who directly configure Terminus, investigate incidents, carry out response work, or review its reports.

## Application Goals

1. **Reduce cybersecurity alert overload** by automatically filtering low-priority events and directing attention to alerts that require investigation or escalation.
2. **Improve the speed and consistency of initial incident investigation** by collecting relevant evidence and generating a structured severity and confidence assessment.
3. **Keep human analysts in control** by making AI findings reviewable and reserving consequential response decisions for authorized users.
4. **Protect each customer's information** through organization-level data separation, authentication, and role-based authorization.
5. **Support flexible and isolated deployments** through replaceable SIEM, AI, ticketing, and notification providers, including local or offline-compatible configurations.
6. **Create an auditable incident workflow** that records alerts, investigation results, tickets, notifications, and analyst decisions.

## Main Application Features

1. **SIEM Alert Ingestion and Validation:** Receives Wazuh-compatible security alerts through an API and converts untrusted alert data into validated application records.
2. **Deterministic Alert Triage:** Applies configurable policy rules to classify alerts for ignoring, investigation, or escalation before using an AI service.
3. **AI-Assisted Forensic Investigation:** Collects available alert and host context and generates a structured verdict containing severity, confidence, a forensic summary, and recommended actions.
4. **Incident Management Dashboard:** Displays incident tickets and their evidence, status, priority, and mitigation information so analysts can review and manage investigations.
5. **Ticketing and Multi-Channel Notifications:** Creates incident tickets and sends alerts through configurable logging, Slack, SMS, or Jira integrations.
6. **Multi-Tenant Access Management:** Separates organizational data and provides user authentication, organization membership, role-based permissions, and license-based feature entitlements.
