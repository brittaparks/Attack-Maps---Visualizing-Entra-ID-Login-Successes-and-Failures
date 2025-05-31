# Attack-Maps---Visualizing-Entra-ID-Login-Successes-and-Failures


<img width="1616" alt="image" src="https://github.com/user-attachments/assets/61ec08e2-b72e-4bc7-95f8-d6e59c0be635">


<img width="1616" alt="image" src="https://github.com/user-attachments/assets/d66932fe-2581-48e7-8d21-9312a998b756">



<img width="1616" alt="image" src="https://github.com/user-attachments/assets/ff6a4c83-e54e-474f-8052-0af184be57e6">


<img width="1616" alt="image" src="https://github.com/user-attachments/assets/cbce2381-4e8c-42dc-8f8d-b6551bb45881">




## 📌 Project Objective

This project visualizes authentication successes and failures in Azure Entra ID over a 30-day period. By comparing these events geographically, the goal is to uncover potentially suspicious login behavior — such as brute force attempts, anomalous geolocations, and patterns that may indicate identity-based attacks.

---

## 🔍 Why This Matters

Monitoring authentication patterns helps:
- Detect early signs of brute force activity
- Correlate failed logins to successful ones across locations
- Identify unusual geographic login patterns (e.g., impossible travel)
- Improve incident response by enriching alerts with geolocation context

---

## 🛠️ Tools & Data Sources

| Tool | Purpose |
|------|---------|
| Microsoft Sentinel | Querying SigninLogs from Azure AD |
| KQL (Kusto Query Language) | Writing analytics rules and custom queries |
| Azure Map Visualization | Displaying geo-based login patterns |
| Entra ID SigninLogs | Authentication telemetry |
| Watchlists (optional) | For IP enrichment with city/country |

---

## 🧪 Methodology

1. **Query SigninLogs** for both successful and failed logins
2. **Extract geolocation data** from `LocationDetails`
3. **Group by Identity**, compute average coordinates and counts
4. **Truncate identity** to the first 8 characters for anonymity
5. **Label map points** using `city` and `countryOrRegion`
6. **Visualize** each result set on a heatmap

---

### ✅ Successful Logins

- Shows typical user login behavior
- Helps establish baseline activity
- Example label format: `michael@... – Atlanta, US`

Log Analytics workspace Logs (Analytics) KQL Query 
```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResultType == 0
| where isnotempty(Identity)
| extend Latitude = todouble(LocationDetails["geoCoordinates"]["latitude"]),
         Longitude = todouble(LocationDetails["geoCoordinates"]["longitude"]),
         City = tostring(LocationDetails["city"]),
         Country = tostring(LocationDetails["countryOrRegion"])
| where isnotnull(Latitude) and isnotnull(Longitude)
| where isnotempty(City) and isnotempty(Country)
| summarize SuccessLoginCount = count(), 
            Latitude = avg(Latitude), 
            Longitude = avg(Longitude), 
            City = any(City), 
            Country = any(Country) by Identity
| extend ShortIdentity = substring(Identity, 0, 8)
| extend friendly_label = strcat(ShortIdentity, " - ", City, ", ", Country)
| project Identity, SuccessLoginCount, Latitude, Longitude, friendly_label
| order by SuccessLoginCount desc 
```
Json - Advanced Editor Settings
```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SigninLogs\n| where TimeGenerated >= ago(30d)\n| where ResultType == 0\n| where isnotempty(Identity)\n| extend Latitude = todouble(LocationDetails[\"geoCoordinates\"][\"latitude\"]),\n         Longitude = todouble(LocationDetails[\"geoCoordinates\"][\"longitude\"]),\n         City = tostring(LocationDetails[\"city\"]),\n         Country = tostring(LocationDetails[\"countryOrRegion\"])\n| where isnotnull(Latitude) and isnotnull(Longitude)\n| where isnotempty(City) and isnotempty(Country)\n| summarize SuccessLoginCount = count(), \n            Latitude = avg(Latitude), \n            Longitude = avg(Longitude), \n            City = any(City), \n            Country = any(Country) by Identity\n| extend ShortIdentity = substring(Identity, 0, 8)\n| extend friendly_label = strcat(ShortIdentity, \" - \", City, \", \", Country)\n| project Identity, SuccessLoginCount, Latitude, Longitude, friendly_label",
    "size": 0,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "latitude": "Latitude",
      "longitude": "Longitude",
      "sizeSettings": "SuccessLoginCount",
      "sizeAggregation": "Sum",
      "minData": 1,
      "labelSettings": "friendly_label",
      "legendMetric": "SuccessLoginCount",
      "numberOfMetrics": 6000,
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "SuccessLoginCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - successful_login_map_with_short_identity"
}
```

### ❌ Failed Logins

- Highlights login failures from distinct locations
- Helps correlate potential brute force campaigns
- Identifies login attempts from unexpected regions


Log Analytics workspace Logs (Analytics) KQL Query 
```kql
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResultType != 0
| extend Latitude = todouble(LocationDetails["geoCoordinates"]["latitude"]), Longitude = todouble(LocationDetails["geoCoordinates"]["longitude"])
| where isnotnull(Latitude) and isnotnull(Longitude)
| where isnotempty(Identity)
| summarize FailedLoginCount = count(), Latitude = avg(Latitude), Longitude = avg(Longitude), City = any(tostring(LocationDetails["city"])), Country = any(tostring(LocationDetails["countryOrRegion"])) by Identity
| extend ShortIdentity = substring(Identity, 0, 8)
| extend friendly_label = strcat(ShortIdentity, " - ", City, ", ", Country)
| project Identity, FailedLoginCount, Latitude, Longitude, friendly_label
| order by FailedLoginCount desc
```
Json - Advanced Editor Settings
```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SigninLogs\n| where TimeGenerated >= ago(30d)\n| where ResultType != 0\n| extend Latitude = todouble(LocationDetails[\"geoCoordinates\"][\"latitude\"]), Longitude = todouble(LocationDetails[\"geoCoordinates\"][\"longitude\"])\n| where isnotnull(Latitude) and isnotnull(Longitude)\n| where isnotempty(Identity)\n| summarize FailedLoginCount = count(), Latitude = avg(Latitude), Longitude = avg(Longitude), City = any(tostring(LocationDetails[\"city\"])), Country = any(tostring(LocationDetails[\"countryOrRegion\"])) by Identity\n| extend ShortIdentity = substring(Identity, 0, 8)\n| extend friendly_label = strcat(ShortIdentity, \" - \", City, \", \", Country)\n| project Identity, FailedLoginCount, Latitude, Longitude, friendly_label",
    "size": 0,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "latitude": "Latitude",
      "longitude": "Longitude",
      "sizeSettings": "FailedLoginCount",
      "sizeAggregation": "Sum",
      "minData": 1,
      "labelSettings": "friendly_label",
      "legendMetric": "FailedLoginCount",
      "numberOfMetrics": 6000,
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "FailedLoginCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - failed_login_map_with_short_identity"
}
```

## ⚠️ Limitations & Considerations

- 🌍 **Geolocation is not always accurate**  
  IP-based location can be masked by VPNs, proxies, or cloud-hosted infrastructure (e.g., AWS, Azure, GCP)

- 📊 **“Others” bucket not visualized**  
  Some records may be anonymized or mapped to placeholder IPs that don’t resolve to real-world coordinates

- 🌐 **Dots in the ocean**  
  Often caused by missing or malformed geoCoordinates (e.g., lat=0, long=0)

- 📉 **Small-value locations not shown**  
  Maps may suppress points with very low login counts to reduce clutter

---

## 🧠 What We Can Learn at a Glance

- Clusters of failed logins from multiple countries may suggest **brute force activity**
- Successes vs. failures mapped together highlight **anomalous behavior**
- Visualizing patterns geographically gives faster **situational awareness** during investigations

---

## 📊 Observations from This Data Set

Within the 30-day window:

- Some accounts had failed login attempts ranging from **2 to 211** — possible brute force attempts or misconfigurations
- Successful logins per account ranged from **1 to 503** — consistent with expected daily use and some service accounts
- No sharp geographic anomalies or coordinated attack patterns were observed
- These results are typical for a **low-noise test range**, but still reinforce the value of **early detection through visualization**


---
### 📇 Analyst Contact

**Name**: Britt Parks\
**Contact: [linkedin.com/n/brittaparks](https://linkedin.com/n/brittaparks)**\
**Date**: May 31, 2025
