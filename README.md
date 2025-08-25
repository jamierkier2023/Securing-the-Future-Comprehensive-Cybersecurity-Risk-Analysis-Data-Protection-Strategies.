# Securing-the-Future: Cybersecurity-Risk-Analysis & Data-Protection-Strategies
This is a  market analysis, by way of EDA exploratory data analysis for an energy business looking for entry and exit strategies. 

# Cybersecurity Risk Analysis Project

## Project Overview
This project, **Cybersecurity Risk Analysis: Analyze cybersecurity risks for a company and recommend measures to protect sensitive data and infrastructure**, is designed at an **intermediate level** of data analytics. This project analyzes **LOCK Co.’s cybersecurity risks** using SQL queries and data visualization.  
It aims to detect vulnerabilities, assess threats, and provide actionable recommendations to protect sensitive data, ensure compliance, and maintain client trust.  
The primary tool used is **PostgreSQL**, focusing on **cybersecurity analysis** to evaluate risks and propose actionable security improvements.

## Specialization & Tools
- **Specialization:** Cybersecurity Analysis  
- **Business Focus:** General  
- **Primary Tool:** PostgreSQL  
---

## Learning Skills Developed
- SQL Query Optimization  
- Data Cleaning and Transformation  
- Data Manipulation  
- Exploratory Data Analysis  

---
## Company Context (LOCK Co.)
LOCK Co. is a **mid-sized technology company** specializing in **software development and IT services**.  
- Founded in **2010**, now employing ~100 staff.  
- Operates primarily in the **United States** with a diverse client portfolio (SMBs, education, nonprofits).  
- Services include **custom software development, IT consulting, maintenance, and support**.  
- Known for **innovation, customer satisfaction, and cost-effective solutions** across industries like **healthcare, retail, and education**.  

### Cybersecurity Challenges
Despite its growth, LOCK Co. faces significant cybersecurity threats, including:  
- **Phishing attempts**  
- **Malware infections**  
- **Unauthorized access to sensitive data**  
- **Increasing cyberattack frequency targeting mid-sized businesses**  

---
## Significance of the Project
The project is critical due to several strategic concerns:  
- **Protection of Sensitive Data** – safeguard client data to avoid financial loss & reputational harm.  
- **Compliance Requirements** – adherence to evolving regulations to prevent penalties.  
- **Client Trust** – maintaining trust by demonstrating strong cybersecurity practices.  
- **Business Continuity** – mitigating risks that can disrupt operations.  
- **Reputation Management** – strengthening LOCK Co.’s image in a competitive industry.  

---
## Project Objectives
The cybersecurity risk analysis aims to:  
1. Conduct a **comprehensive risk assessment** to identify vulnerabilities and threats.  
2. Develop a **tailored cybersecurity strategy** based on LOCK Co.’s needs and risk profile.  
3. Implement **cybersecurity measures** to protect sensitive data and infrastructure.  
4. Ensure **compliance** with cybersecurity regulations.  
5. Enhance **incident response and recovery capabilities**.  

---
## Methodology
The project methodology is structured around SQL-based analytics:  
1. **Data Aggregation & Cleaning** – Using SQL queries to clean and prepare data for analysis.  
2. **Exploratory Analysis** – Executing advanced SQL queries to uncover patterns and risks.  
3. **Statistical Analysis** – Applying SQL functions for insight generation.  
4. **Documentation & Review** – Capturing findings, reviewing outcomes, and evaluating solutions with SQL evidence.  

## Table of Contents
1. [Project Overview](#project-overview)
2. [Threats by Severity](#threats-by-severity)
3. [Traffic Volume by Type](#traffic-volume-by-type)
4. [Distribution of Threat Types](#distribution-of-threat-types)
5. [Failed MFA Attempts](#failed-mfa-attempts)
6. [Encryption Algorithm Usage](#encryption-algorithm-usage)
7. [Trend of High & Critical Threats](#trend-of-high--critical-threats)
8. [Insights & Recommendations](#insights--recommendations)
9. [Conclusion](#conclusion)

---
---
## Threats by Severity
**SQL Query:**【30†source】
```sql
-- Categorize and summarize severity levels
-- (Assumes Severity_Category already derived from Severity_Level)
SELECT 
    SUM(CASE WHEN Severity_Category = 'High Risk' THEN 1 ELSE 0 END) as High_Risk_Count,
    SUM(CASE WHEN Severity_Category = 'Low Risk' THEN 1 ELSE 0 END) as Low_Risk_Count,
    SUM(CASE WHEN Severity_Category = 'Medium Risk' THEN 1 ELSE 0 END) as Medium_Risk_Count
FROM network_logs_2;
```
**Visualization:**  
<img width="1200" height="800" alt="01_severity_distribution" src="https://github.com/user-attachments/assets/3cbb1ad6-596b-47f2-ad5a-8208f88f2ce9" />


---

## Traffic Volume by Type
**SQL Query:**【30†source】
```sql
-- Total data volume across traffic categories
SELECT Traffic_Category, SUM(Data_Volume) as Total_Data_Volume 
FROM network_logs
GROUP BY Traffic_Category 
ORDER BY Total_Data_Volume DESC;
```
**Visualization:**  
<img width="1200" height="800" alt="02_traffic_distribution" src="https://github.com/user-attachments/assets/93653d58-b017-43e3-b28d-3aafb6382be2" />


---

## Distribution of Threat Types
**SQL Query:**【30†source】
```sql
-- Count events by threat type
SELECT B.Threat_Type, COUNT(*) as Threat_Count
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
GROUP BY B.Threat_Type
ORDER BY Threat_Count DESC;
```
**Visualization:**  
<img width="1200" height="800" alt="03_threat_types" src="https://github.com/user-attachments/assets/29cdd3c7-4b85-40b5-9110-324b59073b1b" />


---

## Failed MFA Attempts
**SQL Query:**【30†source】
```sql
-- Rank sources by failed MFA attempts
SELECT 
    Source_IP, 
    COUNT(ID) as Failed_Attempts
FROM network_logs
WHERE MFA_Status = 'Failed'
GROUP BY Source_IP
ORDER BY Failed_Attempts DESC;
```
**Visualization:**  
<img width="1200" height="800" alt="04_failed_mfa" src="https://github.com/user-attachments/assets/39097b4a-b7d0-4e00-92e6-cae3d6069a60" />


---

## Encryption Algorithm Usage
**SQL Query:**【30†source】
```sql
-- Frequency of encryption algorithms for sensitive data
SELECT A.Encryption_Algorithm, COUNT(*) as Frequency
FROM network_logs A
WHERE A.Data_Classification IN ('Confidential', 'Highly Confidential')
GROUP BY A.Encryption_Algorithm
ORDER BY Frequency DESC;
```
**Visualization:**  
<img width="1200" height="800" alt="05_encryption_usage" src="https://github.com/user-attachments/assets/92ad7a02-53a5-4678-8852-5b2e249416cb" />


---

## Trend of High & Critical Threats
**SQL Query:**【30†source】
```sql
-- Monthly trend of high/critical events
SELECT DATE_TRUNC('month', A.Timestamp) AS Month, COUNT(*) as Critical_High_Count
FROM network_logs A
JOIN network_logs_2 B ON A.ID = B.Linked_ID
WHERE B.Severity_Level IN ('High', 'Critical')
GROUP BY DATE_TRUNC('month', A.Timestamp)
ORDER BY Month;
```
**Visualization:**  
<img width="1200" height="800" alt="06_trend_high_critical" src="https://github.com/user-attachments/assets/6ca26f03-22f8-4b2d-8c4a-66a9206edfbc" />


---

## Insights & Recommendations
### Key Insights
- **Severity:** Medium-risk threats are most frequent, with **high-risk events trending upward**.
- **Traffic:** **Outgoing traffic > Incoming**, suggesting potential **data exfiltration** vectors.
- **Threat Mix:** Malware and DDoS dominate event volume, with notable **phishing** presence.
- **Authentication:** **Failed MFA** attempts cluster around a few IPs → likely **targeted brute-force**.
- **Encryption:** Some confidential data uses **weak/unknown algorithms**, creating exposure.

### Recommendations (Actionable)
1. **Harden Authentication**: Enforce stricter MFA policies; implement rate-limiting and IP blacklisting; alert on abnormal login patterns.
2. **Standardize Encryption**: Mandate **AES-256** for all confidential/highly confidential data; audit and remediate “Unknown” algorithms.
3. **Monitor Exfiltration**: Deploy egress anomaly detection (DLP rules, sudden spikes, unusual destinations) and block suspicious flows.
4. **Bolster Endpoint & Network Security**: EDR + IDS/IPS tuning against **Malware/DDoS/Phishing** playbooks; sandbox suspicious payloads.
5. **Firewall Rule Hygiene**: Review high-trigger rules; convert noisy allows to **least-privilege** denies where feasible.
6. **Incident Response Readiness**: Establish runbooks for **High/Critical** events with defined RTO/RPO; run tabletop exercises quarterly.

**Operational KPIs to Track**
- Mean time to detect/respond (MTTD/MTTR) for high/critical incidents  
- % of confidential data covered by **AES-256**  
- MFA failure rate by source and **block rate** for repeated offenders  
- **Outbound** data volume anomalies (Z-score/Sigma rules)  
- Patch/EDR policy compliance rates

---

## Conclusion
This self-contained README ties **SQL evidence** to **visual outcomes** and a prescriptive plan.  
Executing the recommendations will reduce risk exposure, improve compliance, and strengthen client trust.
