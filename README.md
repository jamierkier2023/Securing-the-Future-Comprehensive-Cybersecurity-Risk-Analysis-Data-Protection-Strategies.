# Securing-the-Future: Cybersecurity-Risk-Analysis & Data-Protection-Strategies
This is a  market analysis, by way of EDA exploratory data analysis for an energy business looking for entry and exit strategies. 

# Cybersecurity Risk Analysis Project

## Table of Contents

1.  [Project Overview](#project-overview)
2.  [Problem Statement](#problem-statement)
3.  [SQL Code](#sql-code)
4.  [Visual Storyline (PNG Files)](#visual-storyline-png-files)
5.  [Insights](#insights)
6.  [Recommendations](#recommendations)
7.  [Conclusion](#conclusion)

------------------------------------------------------------------------

## Project Overview

This project demonstrates the use of **PostgreSQL** for analyzing
**cybersecurity risks** faced by a mid-sized IT company (**LOCK Co.**).\
The goal is to identify vulnerabilities, classify threats, and recommend
measures to protect sensitive data and infrastructure.

------------------------------------------------------------------------

## Problem Statement

**LOCK Co.** faces cybersecurity challenges including:\
- Rising **high-risk threats** (malware, phishing, DDoS).\
- **Failed MFA attempts** from suspicious IPs.\
- Inconsistent use of **encryption algorithms** for confidential data.\
- Higher **outgoing traffic volumes**, suggesting possible data
exfiltration.\
- Need for compliance with cybersecurity regulations and maintaining
client trust.

------------------------------------------------------------------------

## SQL Code

The SQL queries include:\
- **Data Cleaning & Preparation**: Removing duplicates, handling nulls,
standardizing encryption values.\
- **Data Transformation**: Categorizing threats by severity, traffic by
type.\
- **Exploratory Analysis**: Threat distributions, MFA failures, firewall
effectiveness.\
- **Trend Analysis**: Tracking high/critical events over time.

📄 [Full SQL Code](./Cybersecurity_sql_query.sql)

------------------------------------------------------------------------

## Visual Storyline (PNG Files)

The following PNGs present the executive summary analysis:

1.  ![Severity Distribution](./01_severity_distribution.png)\
    Distribution of **High, Medium, and Low risk threats**.

2.  ![Traffic Distribution](./02_traffic_distribution.png)\
    **Incoming vs Outgoing traffic** to assess attack surface.

3.  ![Threat Types](./03_threat_types.png)\
    Breakdown of **Malware, DDoS, Phishing, Insider Threats**.

4.  ![Failed MFA Attempts](./04_failed_mfa.png)\
    **Top risky IPs** associated with failed MFA login attempts.

5.  ![Encryption Usage](./05_encryption_usage.png)\
    Algorithms applied to protect confidential data (**AES-256, AES-128,
    DES, Unknown**).

6.  ![Threat Trends](./06_trend_high_critical.png)\
    **High and Critical Threat Trends** over time.

------------------------------------------------------------------------

## Insights

1.  **Medium-risk threats** are most frequent, but **high-risk events
    are steadily rising**.\
2.  **Failed MFA attempts** are heavily concentrated among a few IPs,
    indicating **targeted attacks**.\
3.  Encryption practices are inconsistent, with some confidential data
    using **weak or unknown algorithms**.\
4.  Outgoing traffic volume exceeds incoming traffic, suggesting
    potential **data exfiltration risk**.\
5.  Malware and DDoS are the most **common threat categories**,
    requiring stronger defensive measures.

------------------------------------------------------------------------

## Recommendations

✅ **Strengthen Authentication:** Enforce stricter MFA policies, block
suspicious IPs, and monitor anomalies.\
✅ **Upgrade Encryption:** Mandate **AES-256** for all sensitive and
confidential data.\
✅ **Improve Monitoring:** Deploy intrusion detection systems for
unusual **outbound traffic**.\
✅ **Phishing Defense:** Conduct **regular awareness training** for
employees.\
✅ **Firewall Effectiveness:** Continuously review rules to block
repeated attack vectors.\
✅ **Incident Response:** Develop a **rapid response plan** for critical
and high-severity incidents.

------------------------------------------------------------------------

## Conclusion

By leveraging SQL queries and visual analytics, this project highlights
critical cybersecurity risks and provides actionable strategies to
mitigate them.\
Implementing these recommendations will help **LOCK Co.**:\
- Protect sensitive data\
- Maintain compliance\
- Enhance client trust\
- Strengthen overall security posture

------------------------------------------------------------------------
