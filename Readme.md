Run on ubuntu:



bpftrace:

```
docker run --privileged -v /sys:/sys:ro -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -it quay.io/iovisor/bpftrace:v0.11.4 bash
```

bcc:

```
docker run --privileged -v /sys:/sys:ro -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --workdir /usr/share/bcc/tools -it quay.io/iovisor/bcc:v0.17.0-bionic-release bash
```
