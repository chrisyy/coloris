What's included:
-kernel patch for 3.8.8 i386
-kernel config file
-kernel module
-user-level debugging tool (checker)


Module usage:
insmod alloc.ko apps=... qos_pair=...
For apps parameter, pass in applications' process names (as in 
task_struct->comm);
For qos_pair, pass in application-specific QoS requirement (high thred, 
low thred), which should be integers no larger than 100; set to any 
negative integer if want to use system-wide thresholds;
e.g.
insmod alloc.ko apps=gobmk,hmmer qos_pair=70,30,-1,-1

Load the module first, then start applications.


Notes:
-Make sure the memory pool size is appropriate, given hardware RAM size, 
since memory pool only takes memory pages from HighMem.

-Generally speaking, process data and code pages can both be allocated 
within its own context. In the module, page coloring based on file name 
is just a hack to deal with SPEC runspec script. runspec will not start 
programs directly, but copying them to a new directory and starting them. 
This copying means code pages for a process are allocated in page cache 
before the process gets created.

-giveBack is used to ensure that when a process expands color assignment 
and is not using all local page colors, it will get new local page colors 
first. It is currently not generic, but for 8 processes running on 4 
cores so each page color can be shared by 2 processes. For an over-
committed system with flexible number of processes, the implementation 
needs small fix.

-Please refer to "COLORIS: A Dynamic Cache Partitioning System Using 
Page Coloring" (PACT'14) for further information.
