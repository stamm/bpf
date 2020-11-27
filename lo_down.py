#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# lo_down detect when lo interface set down only on host network.
#           For Linux, uses BCC, eBPF.
#
# USAGE: lo_down
#
# Copyright (c) 2020 Rustam Zagirov.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Nov-2020   Rustam Zagirov   Created this.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
import os

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/netdevice.h>
#include <linux/ns_common.h>
#include <linux/netlink.h>

#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)

#define member_address(source_struct, source_member) \
({                                                   \
  void* __ret;                                       \
  __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
  __ret;                                             \
})

struct data_t {
    u64 ts;
    u64 ns;
    u32 pid;
    char comm[80];
    u32 kernel_stack_id;
    u32 user_stack_id;
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1024);


int kprobe__dev_change_flags(struct pt_regs *ctx, struct net_device *dev, unsigned int flags, struct netlink_ext_ack *extack) {
    if (flags != 8) {
        return 0;
    }
    struct data_t data = {};
    
    struct net* net;
    // Get netns id. Equivalent to: evt.netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common* ns = member_address(net, ns);

    unsigned int inum;
    member_read(&inum, ns, inum);

    if (inum != ROOT_NET_NS) {
        return 0;
    }

    // bpf_trace_printk("name: %s, ns: %u, flags: %x\\n", dev, inum, flags);
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns() / 1000;
    data.ns = inum;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
;
"""
path = os.readlink('/proc/1/ns/net')
root_ns = path[5:-1]
bpf_text = bpf_text.replace('ROOT_NET_NS', root_ns)

# b.attach_kprobe(event="dev_change_flags", fn_name="change")

# header
print("Tracing... Ctrl-C to end.")
print("%-18s %-6s %-20s %-10s %s" % ("TIME(s)", "PID", "COMM", "NET NS", "CALL"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-18.9f %-6d %-20s %-10d Hello, World!" % ((float(event.ts) / 1000000),
        event.pid, event.comm, event.ns))
    for addr in stack_traces.walk(event.kernel_stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)
    for addr in stack_traces.walk(event.user_stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)

b = BPF(text=bpf_text)
b["events"].open_perf_buffer(print_event)
stack_traces = b.get_table("stack_traces")
# output
while (1):
    try:
        b.perf_buffer_poll()
        # b.trace_print()
    except KeyboardInterrupt:
        exit()
