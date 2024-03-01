NOTICE: THIS PROJECT IS USE FOR STUDY AND RESEARCH PURPOSES ONLY!

Using Visual Studio to open .sln file and complie project.
Payload in .c file: meterpreter reverse_tcp 192.168.56.129:7777.
Change payload yourself with any .bin file. Remember to convert payload to ipv6fuscation using HellShell.exe.

Some Features:
1. Payload obfuscation (static scan evasion).
2. Sandbox detection (check ram).
3. Use Indirect Syscalls (bypass DLL hooking).
4. Startup Persistence.

How does it work?
1. Program detect sandbox if ram lower 1GB.
2. It takes a snapshot and finds PID of explorer.exe.
3. Take process handle of explorer.exe and allocate memory.
4. Copy & deobfuscate payload to that memory, create remote thread to run payload.
5. Copy itself to startup folder for persistence.
