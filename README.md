# http-sniffer
This project was created as a homework given at Computer Networks class in BMSTU.
The task was to write a sniffer, to sniff all http packets sent. 
If content-type is urlencoded, than all payload of http packet should be printed in style key  = value 

####Compilation:

```
gcc main.cpp -o main -lpcap
```

####Launch:

```
sudo ./main
```

