Sample and benchmark scripts for pktgen (packet generator)
==========================================================
This directory contains some pktgen sample and benchmark scripts, that
can easily be copied and adjusted for your own use-case.

General doc is located in kernel: Documentation/networking/pktgen.txt

Helper include files
====================
This directory contains two helper shell files, that can be "included"
by shell source'ing.  Namely "functions.sh" and "parameters.sh".

Common parameters
-----------------
The parameters.sh file support easy and consistant parameter parsing
across the sample scripts. For how to run:

 ./pktgen_sample01_simple.sh -h

The global variable being set is also listed.  E.g. the required
interface/device parameter "-i" sets variable $DEV.

Common functions
----------------
The functions.sh file provides; Three different shell functions for
configuring the different components of pktgen: pg_ctrl(), pg_thread()
and pg_set().

These functions correspond to pktgens different components.
 * pg_ctrl()   control "pgctrl" (/proc/net/pktgen/pgctrl)
 * pg_thread() control the kernel threads and binding to devices
 * pg_set()    control setup of individual devices

See sample scripts for usage examples.
