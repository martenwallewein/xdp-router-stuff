# XDP SCION Router - Bunch of testing stuff

## Build and run the mock (userspace) implementation
```
cd mock
gcc userspace_test.c
./a.out
```

Listens on :8080 for incoming UDP packets and thinks that all of them are SCION packets
Just for testing purposes, may be easier to test compared to eBPF.