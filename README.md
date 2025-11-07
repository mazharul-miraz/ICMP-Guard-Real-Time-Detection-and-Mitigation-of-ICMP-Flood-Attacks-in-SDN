ICMP Guard – Real-Time ICMP Flood Detection and Mitigation in SDN
Project Overview

ICMP Guard is a capstone project that demonstrates real-time detection and mitigation of ICMP flood attacks in a Software-Defined Network (SDN) environment. The project leverages the Ryu SDN controller, a virtualized network testbed using Mininet, and Linux-based tools to monitor, detect, and mitigate malicious ICMP traffic while maintaining normal network operations.

Key Features

Real-time ICMP traffic monitoring using the Ryu controller
Threshold-based detection to identify ICMP flood attacks
Automated mitigation by blocking malicious hosts dynamically
Data logging for attack analysis (icmp_host_log.csv)
Visualization dashboard for network traffic monitoring (Plotly Dash)
Fully developed and tested in a virtual Linux environment

Installation / Setup
Prerequisites
Linux OS (Ubuntu recommended)
Python 3.x
Mininet
Ryu SDN controller
Required Python packages: pandas, plotly, flask

Setup Steps 

Start the Mininet topology:
Launch the Ryu controller with the ICMP Guard application:  """ryu-manager icmp_guard.py"""


Usage
> Normal traffic test:
ping 10.0.0.3
>ICMP flood attack simulation:
hping3 -1 --flood 10.0.0.3

Project Structure
icmp-guard/
│
├── icmp_guard.py         # Ryu controller application
├── visual.py              # Static visualization
├── icmp_host_log.csv     # Logging of ICMP activity
└── README.md

License [This project is for academic purposes and is not licensed for commercial use.]
