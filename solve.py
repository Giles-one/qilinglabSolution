import struct
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.os.mapper import QlFsMappedObject

ql = Qiling(
	argv = ["./qilinglab-x86_64"], 
	rootfs = "/", 
	verbose = QL_VERBOSE.OFF
	)


## chall1
ql.mem.map(addr = 0x1337 // 0x1000 * 0x1000, size = 0x1000)
ql.mem.write(addr = 0x1337, data = struct.pack("<I", 1337))


## chall2
def uname_syscall_hook(ql: Qiling, buf, *args, **kwargs) -> int:
	ql.mem.write(buf, b'QilingOS\x00')
	ql.mem.write(buf + 0xC3, b'ChallengeStart\x00')
	return args[0]
ql.os.set_syscall('uname', uname_syscall_hook, QL_INTERCEPT.EXIT)


## chall3
class FakeUrandom(QlFsMappedObject):
	def read(self, size: int) -> bytes:
		if size == 0x20:
			return b'A' * size  # take care of the type(bytes) of return value 
		elif size == 0x1:
			return b'B' * size
		else:
			return b'C' * size
	def close(self) -> int:
		return 0
def getrandom_syscall_hook(ql: Qiling, buf, buflen, flags, *args, **kargs) -> int:
	ql.mem.write(buf, b'A' * buflen)
	return buflen
ql.add_fs_mapper('/dev/urandom', FakeUrandom())
ql.os.set_syscall('getrandom', getrandom_syscall_hook, QL_INTERCEPT.CALL)


# chall4
def hook_cmp(ql: Qiling) -> None:
	ql.arch.regs.write('eax', 0x1)
base = ql.mem.get_lib_base('qilinglab-x86_64')
ql.hook_address(hook_cmp, base + 0xE43)


# chall5
def rand_api_hook(ql: Qiling, *args, **kwargs) -> int:
	ql.arch.regs.eax = 0
ql.os.set_api('rand', rand_api_hook, QL_INTERCEPT.CALL)


# chall6
def hook_cmp2(ql: Qiling) -> None:
	ql.arch.regs.write('eax', 0)
ql.hook_address(hook_cmp2, base + 0xF16)


# chall7
def hook_sleep(ql: Qiling) -> None:
	# ql.arch.regs.write('rip', base + 0xF41)
	ql.arch.regs.write('edi', 0)
ql.hook_address(hook_sleep, base + 0xF3C)


# chall8
def hook_to_find_target(ql: Qiling) -> None:
	target = struct.pack("<Q", 0x3DFCD6EA00000539)
	addrs = ql.mem.search(target)
	for addr in addrs:
		test = struct.unpack("<Q", ql.mem.read(addr-8, 8))[0]
		if ql.mem.string(test) == 'Random data':
			flag_pointer = struct.unpack("<Q", ql.mem.read(addr + 8, 8))[0]
			ql.mem.write(flag_pointer, struct.pack('<b', 1))
ql.hook_address(hook_to_find_target, base + 0xFB5)


# chall9
def tolower_api_hook(ql: Qiling, *args, **kwargs) -> None:
	pass
ql.os.set_api('tolower', tolower_api_hook, QL_INTERCEPT.CALL)


# chall10
class FakeCmdLine(QlFsMappedObject):
	def read(self, size: int) -> bytes:
			return b'qilinglab'
	def close(self) -> int:
		return 0
ql.add_fs_mapper('/proc/self/cmdline', FakeCmdLine())


# chall11
def hook_cpuid(ql: Qiling, address: int, size: int):
	if ql.mem.read(address, size) == b'\x0F\xA2':
		ql.arch.regs.ebx = 0x696C6951
		ql.arch.regs.ecx = 0x614C676E
		ql.arch.regs.edx = 0x20202062
		ql.arch.regs.rip += 2
ql.hook_code(hook_cpuid)

ql.run()

