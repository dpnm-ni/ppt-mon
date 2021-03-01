# PPTMon
VNF Packet Processing Time Monitoring

## Requirements
- Linux kernel >= 5.3. We tested PPTMon with Ubuntu 19.10 kernel 5.3, and Ubuntu 20.04 kernel 5.4.

## Installation
- Install [BCC](https://github.com/iovisor/bcc) from source. PPTMon is tested with BCC v0.18.0.
- Install requirements
    ```bash
    sudo pip3 install -r requirements.txt
    ```

## Usage
To get help on how to use PPTMon, run
```bash
sudo python3 -m pptmon -h
```

## Publication
To understand how PPTMon works, please refer the following publication
- N. V. Tu, J. -H. Yoo and J. W. -K. Hong, "Measuring End-to-end Packet Processing Time in Service Function Chaining," *16th International Conference on Network and Service Management (CNSM)*, 2020.

