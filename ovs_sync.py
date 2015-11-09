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

import subprocess
import logging

logging.basicConfig(filename='ovs_sync.log',level=logging.DEBUG)

SYNC_DEFAULT_TABLE_ID = 1
SYNC_DEFAULT_BUNDLE_ID = 0x5AFEC0DE
SYNC_DEFAULT_MONITOR_ID = 0x15EEDEAD
SYNC_CLAIM_MAGIC = 0xD0C0FFEE
SYNC_MEM_MAGIC = 0xD0ACCE55 

TEMP_FILE = r"/tmp/bundle.txt"
DEBUG = False

def OVS_OFCTL(args):
    try:
        cmdline_args = ["ovs-ofctl"] + args + ["-O", "OpenFlow14"]
        logging.debug(str( cmdline_args))
        p = subprocess.Popen(cmdline_args,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        res = [p.returncode,p.communicate()]
        logging.debug(str( res))
        return res
        #return subprocess.check_output(cmdline_args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        logging.warning(str( e))
        #logging.warning(subprocess.Popen.communicate())
        return None



def CONCAT(left, right, size = 32):
    return (left<<size)+right

def LEFT(value,  size = 32):
    return value>>size

def RIGHT(value,  size = 32):
    return value&((1<<size)-1)

def CONCAT3(a, b, c, sizes = [16,16,32]):
    return (a<<(sum(sizes[1:]))) + (b<<(sum(sizes[2:]))) + c

def ONES(size = 32):
    return (1<<size)-1

ADD_FLOW = "add-flow"
DEL_FLOWS = "del-flows"

def get_match(value, mask, datapath):
    return "metadata=0x%x/0x%x"%(value,mask)

def get_instructions(i, datapath):
    return "actions=write_metadata:0x%x/0x%x"%(i,ONES())

def create_command(cmd_type, datapath, match, actions = None, checkoverlap = False ):
    if checkoverlap:
        checkoverlap = "check_overlap"
    else:
        checkoverlap = ''
    if not actions:
        actions = ''
    return [cmd_type, datapath, " ".join([match,checkoverlap,actions])]

def claim(self_id, x, datapath):      
    logging.debug(str( ["claim"] + [self_id, x, datapath]))  
    value = CONCAT3(0, self_id, x)
    mask = CONCAT3(0, ONES(16), ONES(32))
    match = get_match(value, mask, datapath)
    inst = get_instructions(SYNC_CLAIM_MAGIC, datapath)

    cmd = create_command(ADD_FLOW, datapath, match, inst)
    return [cmd]
    
def check(self_id, x, datapath):
    logging.debug(str( ["check"] + [self_id, x, datapath]))  
        
    value = CONCAT3(self_id, 0, x)
    mask = CONCAT3(ONES(16), 0, ONES(32))
    match = get_match(value, mask, datapath)
    inst = get_instructions(SYNC_CLAIM_MAGIC, datapath)

    cmd1 = create_command(ADD_FLOW, datapath, match, inst, True)
    cmd2 = create_command(DEL_FLOWS, datapath, match)
    return [cmd1, cmd2]

def unclaim(self_id, x, datapath):
    logging.debug(str( ["unclaim"] + [self_id, x, datapath]))  
    value = CONCAT3(0, self_id, x)
    mask = CONCAT3(0, ONES(16), ONES(32))
    match = get_match(value, mask, datapath)

    cmd = create_command(DEL_FLOWS, datapath, match)
    return [cmd]
    
def write(addr, k, datapath):
    logging.debug(str( ["write"] + [addr, k, datapath]))  
        
    value = CONCAT(0xFFFFFFFF, addr)
    mask = CONCAT(0, 0xFFFFFFFF)
    match = get_match(value, mask, datapath)
    inst = get_instructions(SYNC_MEM_MAGIC, datapath)

    cmd1 = create_command(DEL_FLOWS, datapath, match)
    
    
    value = CONCAT(0xFFFFFFFF, addr)
    mask = CONCAT(k, 0xFFFFFFFF)
    match = get_match(value, mask, datapath)
    inst = get_instructions(SYNC_MEM_MAGIC, datapath)
    
    cmd2 = create_command(ADD_FLOW, datapath, match, inst)
    return [cmd1, cmd2]

def compare(addr, k, datapath):
    logging.debug(str( ["compare"] + [addr, k, datapath]))  
    value = CONCAT(0xFFFFFFFF, addr)
    mask = CONCAT(k, 0xFFFFFFFF)
    match = get_match(value, mask, datapath)
    inst = get_instructions(SYNC_MEM_MAGIC, datapath)

    cmd = create_command(ADD_FLOW, datapath, match, inst, True)
    return [cmd]

def unsafe_CAS(addr, old, new, datapath):
    return compare(addr, old, datapath) + write(addr, new, datapath)

def send_all(msgs, datapath, with_barriers = False):
    outputs = []
    for msg in msgs:
        outputs.append(OVS_OFCTL(msg))
    return outputs
def fix_command_for_bundle(cmd):
    c = cmd[0]
    cmd[0] = c.replace("add-flows","add").replace("add-flow","add").replace("del-flows","delete").replace("del-flow","delete").replace("mod-flows","modify").replace("mod-flow","modify")
    return [cmd[0]] + cmd[2:]
    
def send_as_bundle(datapath,msgs):
    msgs = map(fix_command_for_bundle, msgs)
    file(TEMP_FILE,"w").write("\n".join(map(" ".join,msgs))+"\n")
    return OVS_OFCTL(["--bundle","add-flows",datapath,TEMP_FILE])

def execute_atomic(datapath, cmds):
    return send_as_bundle(datapath,cmds)
    
def request_config(datapath):
    logging.debug(str( ["request_config"] + [datapath]))  
    return OVS_OFCTL(["dump-flows",datapath])
  
def clear_config(datapath):
    logging.debug(str( ["clear_config"] + [datapath]))  
    return OVS_OFCTL(["del-flows",datapath])
    
def cas(addr, old, new, datapath):
    return execute_atomic(datapath, unsafe_CAS(addr, old, new, datapath))

def parse_config(conf_output):
    flows = conf_output.split("\n")[1:]
    policy = []
    claims = []
    mem = {}
    for flow in flows:
        flow_dict = {}
        items = flow.split(" ")
        
        for item in items:
            item = item.strip()
            if item == '':
                continue
            key,value = item.split("=")
            flow_dict[key] = value
        if (flow_dict.has_key('actions') and \
            flow_dict['actions'] == "write_metadata:0x%x/0xffffffff"%(SYNC_CLAIM_MAGIC,)\
            ):
            value = int(flow_dict['metadata'].split("/")[0],16)
            self_id = value>>32
            rid = value & ONES(32)
            claims.append((self_id, rid))
        elif (flow_dict.has_key('actions') and \
            flow_dict['actions'] == "write_metadata:0x%x/0xffffffff"%(SYNC_MEM_MAGIC,)\
            ):
            value = int(flow_dict['metadata'].split("/")[0],16)
            mask = int(flow_dict['metadata'].split("/")[0],16)
            k = value>>32
            addr = value & ONES(32)
            mem[addr] = k
        else:
            policy.append(flow_dict)
    logging.debug(str( [mem, claims, policy])) 
    return mem, claims, policy
        
def policy_update_with_cas(self_id, update_func, policy_id_addr, datapath):
    global TEMP_FILE
    TEMP_FILE = r"/tmp/bundle.txt"+ str(self_id)
    res = 1
    while res:
        conf_output = request_config(datapath)[1][0]
        mem, claims, policy = parse_config(conf_output)
        if mem.has_key(policy_id_addr):
            pid = mem[policy_id_addr]
        else:
            pid = 0
        update_cmds = update_func(mem, claims, policy)
        bundle_res = execute_atomic(datapath, unsafe_CAS(policy_id_addr, pid, pid+1, datapath) + update_cmds)
        res = bundle_res[0]
        if res:
            print "F",
        else:
            print 'S',
 