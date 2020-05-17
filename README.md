# Honeypot
**A honeypot framework designed to measure drive-by internet attacks**

This project contains a lightweight Go service designed to act as a honeypot
for various drive-by internet attacks on common protocols. It is designed to
make adding new protocols extremely easy, while keeping track of various
indicators of an attack.

## Supported Protocols

| Protocol   | Port  | Emulation   |
|------------|-------|-------------|
| SSH        | 22    | Full        |
| Telnet     | 23    | Full        |
| HTTP       | 80    | Full        |
| RDP        | 3369  | Basic (TCP) |
| VNC        | 5900  | Basic (TCP) |
| Redis      | 6379  | Basic (TCP) |
| MongoDB    | 27017 | Basic (TCP) |
| PostgreSQL | 5432  | Basic (TCP) |
| MySQL      | 3306  | Basic (TCP) |