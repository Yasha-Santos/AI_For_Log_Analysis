# AI For Log Analysis

Our AI For Log Analysis project focuses on using machine learning and automation techniques to analyze system and security logs more efficiently. The goal of this capstone project is to leverage AI to detect patterns, identify suspicious activity or anomalies, and support faster troubleshooting and incident response when issues occur.

This repository contains the project files, source code, datasets, and documentation related to the development, testing, and implementation of our AI-driven log analysis approach.

#### Our repository contains the following folders:

- [POC](https://github.com/Yasha-Santos/AI_For_Log_Analysis/tree/main/POC)
  - [DEPR](https://github.com/Yasha-Santos/AI_For_Log_Analysis/tree/main/POC/DEPR)
- [Scanning Scripts](https://github.com/Yasha-Santos/AI_For_Log_Analysis/tree/main/Scanning%20Scripts)
- [Website](https://github.com/Yasha-Santos/AI_For_Log_Analysis/blob/main/The%20Website/Final_App.zip)

 <img width="1058" height="764" alt="image" src="https://github.com/user-attachments/assets/074140ea-f5e0-4c56-a9ad-201c1ea2bcca" />

#### Threat Reporting:

- We are using AbusdIPdb API and AlienVault API to look up the IPs and get a confidence score and crowdsourced reports on the IP , and if it is flagged it provide an explanation why it was flagged.
- We are also using an offline IPs database to geolocate the country of origin for the IP to lessen the load APIs calling . ( Database used is "GeoLite2-Country.mmdb")


