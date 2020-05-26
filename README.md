# PPTMon
VNF Packet Processing Time Monitoring

# Requirements
- Linux kernel >= 4.13. Tested with kernel v5.4.

# Installation
- Install latest [BCC](https://github.com/iovisor/bcc) from source
- Install requirements
    ```bash
    sudo pip3 install -r requirements.txt
    ```

# Usage
```bash
sudo python3 -m pptmon
```
# Notes
- Reduce the MSS size in iperf so that there is room to increase/decrease
