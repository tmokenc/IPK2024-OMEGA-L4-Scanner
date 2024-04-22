## Implemented
- [x] Argument parser
- [x] Print interfaces
- [x] Scanner
    - [x] Scan function
    - [x] Retranmission
    - [x] Rate limit guard (for ICMP packet)
    - [x] UDP
        - [x] Scanner setup
        - [x] Make header
        - [x] On timeout
        - [x] On packet
    - [x] TCP
        - [x] Scanner setup
        - [x] Make header
        - [x] On timeout
        - [x] On packet
- [x] SIGINT handle

## Problems
- Sometime the SYN packet include 2 other flags (not RST), I cannot find the cause but it has no affect to the scanning process.
- While there is no memory leak, Valgrind shows some problems with memory manipulation.
