EXTERN NtCloseSSN:DWORD
EXTERN NtCreateProcessSSN:DWORD
EXTERN NtOpenProcessSSN:DWORD
EXTERN NtCreateThreadExSSN:DWORD
EXTERN NtWriteVirtualMemorySSN:DWORD
EXTERN NtWaitForSingleObjectSSN:DWORD
EXTERN NtProtectVirtualMemorySSN:DWORD
EXTERN NtAllocateVirtualMemorySSN:DWORD
;EXTERN NtQuerySystemInformationSSN:DWORD
EXTERN NtCreateFileSSN:DWORD
EXTERN NtReadFileSSN:DWORD
EXTERN NtWriteFileSSN:DWORD

EXTERN sysAddrNtClose:QWORD
EXTERN sysAddrNtCreateProcess:QWORD
EXTERN sysAddrNtOpenProcess:QWORD
EXTERN sysAddrNtCreateThreadEx:QWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD
EXTERN sysAddrNtWaitForSingleObject:QWORD
EXTERN sysAddrNtProtectVirtualMemory:QWORD
EXTERN sysAddrNtAllocateVirtualMemory:QWORD
;EXTERN sysAddrNtQuerySystemInformation:QWORD
EXTERN sysAddrNtCreateFile:DWORD
EXTERN sysAddrNtReadFile:DWORD
EXTERN sysAddrNtWriteFile:DWORD

.CODE

;NtQuerySystemInformation PROC
;	mov r10, rcx
;	mov eax, NtQuerySystemInformationSSN
;	jmp QWORD PTR [sysAddrNtQuerySystemInformation]
;NtQuerySystemInformation ENDP

NtOpenProcess PROC
	mov r10, rcx
	mov eax, NtOpenProcessSSN
	jmp QWORD PTR [sysAddrNtOpenProcess]
NtOpenProcess ENDP

NtCreateProcess PROC
	mov r10, rcx
	mov eax, NtCreateProcessSSN
	jmp QWORD PTR [sysAddrNtCreateProcess]
NtCreateProcess ENDP

NtAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, NtAllocateVirtualMemorySSN
	jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, NtWriteVirtualMemorySSN
	jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov r10, rcx
	mov eax, NtProtectVirtualMemorySSN
	jmp QWORD PTR [sysAddrNtProtectVirtualMemory]
NtProtectVirtualMemory ENDP

NtCreateThreadEx PROC
	mov r10, rcx
	mov eax, NtCreateThreadExSSN
	jmp QWORD PTR [sysAddrNtCreateThreadEx]
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
	mov r10, rcx
	mov eax, NtWaitForSingleObjectSSN
	jmp QWORD PTR [sysAddrNtWaitForSingleObject]
NtWaitForSingleObject ENDP

NtClose PROC
	mov r10, rcx
	mov eax, NtCloseSSN
	jmp QWORD PTR [sysAddrNtClose]
NtClose ENDP

NtCreateFile PROC
	mov r10, rcx
	mov eax, NtCreateFileSSN
	jmp QWORD PTR [sysAddrNtCreateFile]
NtCreateFile ENDP

NtReadFile PROC
	mov r10, rcx
	mov eax, NtReadFileSSN
	jmp QWORD PTR [sysAddrNtReadFile]
NtReadFile ENDP

NtWriteFile PROC
	mov r10, rcx
	mov eax, NtWriteFileSSN
	jmp QWORD PTR [sysAddrNtWriteFile]
NtWriteFile ENDP
END