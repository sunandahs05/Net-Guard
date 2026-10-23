# NetGuard

A rule-based network intrusion detection system (NIDS) written in Python.

NetGuard watches network traffic, applies simple threshold rules to spot suspicious
behaviour, and raises alerts. It **detects and reports only**: it never blocks traffic.

## Status

Not completed

## Outline

- Threshold rules for port scans, SYN floods, ICMP floods and excessive connections
- Alert storage in SQLite
- Live capture, `.pcap` analysis and CIC-IDS2017 CSV analysis
- Accuracy, precision, recall and F1 evaluation
- Interactive Streamlit dashboard

## Requirements

Python 3.9 or newer. Install the libraries with:

```
pip install -r requirements.txt
```

