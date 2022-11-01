import json
import rzpipe
from hexdump import hexdump
import hashlib


def reverse_mask(mask):
    mask_reversed = bytearray()
    for b in mask:
        #mask_reversed.append(0xFF&(~b))
        if b == 0xFF:
            mask_reversed += b'\x00'
        else:
            mask_reversed += b'\xFF'  
    return mask_reversed

def process_instr(pipe):
    ao = pipe.cmdj("aoj")[0]
    #print(ao)

    instr, mask = bytearray.fromhex(ao["bytes"]), bytearray.fromhex(ao["mask"])
    new_instr = instr
    ao['rzil'] = 0
    ao['pseudo'] = 0
    op_type = ao['type']
    ignored_types = ['cjmp', 'jmp']
    must_types = ['call']
    #print(ao)
    operands = ao['opex']['operands']

    offsets = [op for op in operands if op["type"] == "mem" and op["base"]=="pc"]

    print(ao['disasm'])
    if (offsets or op_type in must_types) and (op_type not in ignored_types):
        print(ao)
        mask = reverse_mask(mask)
        new_instr = bytearray(i&(~b) for i,b in zip(instr, mask))
    else:

        mask = bytearray(0 for b in mask)
        
    return instr,new_instr, mask



def hash_func(pipe, offset=None):
    afi = pipe.cmdj("afij")[0]

    #print(afi)
    size = afi["size"]

    pdfj = pipe.cmdj("pdfj")
    func_bytes = b''
    mask_bytes = b''
    old_bytes = b''
    for op in pdfj["ops"]:
        pipe.cmd("s 0x%x"%op["offset"])
        old_data, data, mask = process_instr(pipe)
        old_bytes += old_data
        func_bytes += data
        mask_bytes += mask
    h = hashlib.md5()
    print("DUMP:")
    hexdump(old_bytes)
    print("MASKED:")
    hexdump(func_bytes)
    print("MASK:")
    hexdump(mask_bytes)
    h.update(func_bytes)
    h.update(mask_bytes)
    return h.digest(), h.hexdigest()

if __name__ == '__main__':

    pipe = rzpipe.open("a.out")
    pipe.cmd('aaaa;s sym.main')
    #print(pipe.cmd("afl"))
    #print(pipe.cmdj("aflj"))            # evaluates JSON and returns an object
    print(hash_func(pipe))