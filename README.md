# AI For Log Analysis

Our AI For Log Analysis project focuses on using machine learning and automation techniques to analyze system and security logs more efficiently. The goal of this capstone project is to leverage AI to detect patterns, identify suspicious activity or anomalies, and support faster troubleshooting and incident response when issues occur.

This repository contains the project files, source code, datasets, and documentation related to the development, testing, and implementation of our AI-driven log analysis approach.

#### Our POC folder contains the following files:

- [Parsed Log Output File](https://github.com/Yasha-Santos/AI_For_Log_Analysis/blob/main/POC/parsed_logs_output.json)
- [Run Model on File](https://github.com/Yasha-Santos/AI_For_Log_Analysis/blob/main/POC/run_model_on_file.py)
- [SSH Logs](https://github.com/Yasha-Santos/AI_For_Log_Analysis/blob/main/POC/ssh_logs.txt)
- [Unstructured ML Analysis](https://github.com/Yasha-Santos/AI_For_Log_Analysis/blob/main/POC/unstructered_ml_analysis.py)
  - TBD

<img width="1239" height="864" alt="1" src="https://github.com/user-attachments/assets/99de9109-0877-448b-9fbb-e98e19348fc7" />


#### Scanning Functionality:

- We are using AbusdIPdb API and AlienVault APIto look up the IPS and get a confidence score and crowdsourced reports on the IP , and if it is flagged it provide an explanation why it was flagged. 
- We are using VirusTotal API to scan URLs and reports from over 90 different security vendors and URL scanners, giving you a highly accurate, crowdsourced risk report.
- We are also using VirusTotal to chech any file hashes and reporting on it
- We are also checking the ports and portocols used to for port tunneling 
