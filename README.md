# XDP-Router
AF_XDP implementation of the forwarding data path of SCION Border routers

Assumptions:
- We only implement the actual forwarding of SCION L4/UDP packets, all other packets are kept untouched

Limitations:
- Will not work on Single