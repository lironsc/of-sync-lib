"""
Copyright (c) 2015, Liron Schif

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from ovs_sync import *
import os

def mem_test():
    print send_all( write(1234,11,'s1'), 's1')
    print send_all( compare(1234,11,'s1'), 's1')
    print send_all( compare(1234,12,'s1'), 's1')
    print send_all( write(1234,12,'s1'), 's1')
    print send_all( compare(1234,12,'s1'), 's1')
    print request_config('s1')


def claimer_test():
    print send_all( claim(100,7,'s1'), 's1')
    #print send_all( check(100,7,'s1'), 's1')
    print send_all( check(100,8,'s1'), 's1')
    print send_all( check(101,7,'s1'), 's1')
    print send_all( check(101,8,'s1'), 's1')
    print send_all( claim(101,7,'s1'), 's1')
    print send_all( unclaim(100,7,'s1'), 's1')
    print send_all( check(100,7,'s1'), 's1')

def cas_test():
    for i in xrange(10):
        print cas(1000, i, i+1, 's1')
    print request_config('s1')

    print cas(0xabc, 10, 1, 's1')
    print cas(0xabc, 1, 2, 's1')
    print cas(0xabc, 10, 5, 's1')
    print request_config('s1')
    
def policy_update_test():
    if len(os.sys.argv) > 1:
        self_id = int(os.sys.argv[1])
    else:
        self_id = 1
        print clear_config('s1')
        print send_all( write(0xbbbb,1,'s1'), 's1')
    policy_id_addr = 0xabcd
    datapath = 's1'
    update_func = lambda mem, claims, policy: write(0xbbbb,mem[0xbbbb]+1,'s1')
    for i in xrange(1000):
        policy_update_with_cas(self_id, update_func, policy_id_addr, datapath)
    conf_output = request_config(datapath)[1][0]
    mem, claims, policy = parse_config(conf_output)
    print mem, claims, policy
        
#print clear_config('s1')
#mem_test()
#claimer_test()
#cas_test()
policy_update_test()
    