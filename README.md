#PAM CSESSION

This is a PAM (Pluggable Authentication Modules) Module that allows setting of limits on a login session using both cgroups v2 and rlimit systems.

The module creates a new cgroup for every login session. This is mainly intended to limit the number of processes that can be running in a session to prevent forkbombing a system ('forkbombing' is when a process forks into two subprocesses, each of which forks again, resulting in new processes being spawned until the system is unable to cope). However, pam_cgsession can also limit the amount of memory a session can use, the amount of swap memory it can access, the share of processor time it gets, number of files it can open, maximum file size, etc, etc. Some of these restrictions are applied to all processes in the session collectively, some are applied individually to each process.


#BIG FAT WARNING

Firstly, you should be aware that changing your PAM configuration could result in locking yourself out of your own computer systems if you get something wrong or encounter some kind of weird error. 

This PAM module is free software under the Gnu Public Licence version 3, and comes with no express or implied warranties or guarentees of anything. 

# INSTALL

The usual proceedure:

```
./configure
make
make install
```

should work. The 'make install' stage will have to be done as root. This will copy the pam_csession.so file into /lib/security.



# CONFIGURATION

In order to use the cgroups version 2 features of pam_csession a cgroup2 filesystem must be mounted and pam_csession told where it is. By default pam_csession expects this filesystem mounted on /sys/fs/cgroup, but it can be mounted elsewhere and pam_session can be told it's location using the cgroupfs option.

pam_csession.so is configured by adding a line to the appropriate file in /etc/pam.d. So, for example, if we wish to add pam_csession to the 'sshd' service, we would add a line like the following line to /etc/pam.d/sshd

```
session optional pam_csession.so users=alice,bob cgroupfs=/dev/cgroup threads.max=300 cpu.nice=14 mem.high=4G files.max=200 files.size=100M core.size=1M cpu.max=7200 proc.mem=100M
```

pam_csession is a session module, meaning that it's run to set up a session after a user has authenticated. pam_csession has no involvement in user authentication. The value of 'optional' in this configuration just relates to whether the pam_module must return a value indicating success. This is used by authentication modules to indicate whether the user authenticated successfully. As pam_csession is not an authentication module, and always returns 'success', so it can be configured either as 'optional' or 'required'.

The first 3 values in this example are part of the standard PAM config. After these we get configuration values that relate specifically to pam_csession.

 
cgroupfs=<path>      path to where the cgroup2 filesystem is mounted (default=/sys/fs/cgroup)

user=<names>         comma-separated list of users this config applies to (default, all users)

users=<names>         comma-separated list of users this config applies to (default, all users)

threads.max=<value>  maxiumum number of threads in a session (zero means no limit).

cpu.shares=<value>   share of time on the cpu, as defined in the cgroup documentation (zero means nolimit/default share).

cpu.nice=<value>     share of time on the cpu, defined as using the same format as the 'nice' command (-19 -> 20, with -19 being the highest priority and 20 the lowest).

cpu.max=<seconds>    maximum number of seconds an individual process can run for before being killed (zero means no limit) (RLIMIT_CPU).

mem.high=<bytes>     at this value the memory system will start aggressively recovering unusued memory from the session/cgroup (zero means no limit).

mem.max=<bytes>       maximum amount of memory for the entire session/cgroup. This is the max memory used by all processes together (zero means no limit).

swap.max=<bytes>      maximum amount of swap memory for the entire session/cgroup (zero means no limit).

files.max=<value>     maximum number of files open PER PROCESS (zero means no limit) (RLIMIT_NOFILES).

files.size=<blocks>   maximum size of a single file (zero means no limit) (RLIMIT_FSIZE).

core.size=<blocks>    maximum size of a coredump (zero disables coredumps) (RLIMIT_CORE).

proc.mem=<bytes>      maximum memory per process (zero means no limit) (RLIMIT_AS).

Please note that the files.size and  core.size take their values in filesystem blocks, not bytes. A block is usually 512 bytes, but this can depend on the filesystem in use.

Values expressed in bytes or filesystem blocks can be written either as a raw bytecount, or with a multiplier like 'k' 'M' or 'G' to express kilobytes, megabytes or gigabytes.

threads.max sets the cgroup pids.max value. Despite being called pids.max in cgroups, this value actually operates on threads, so the cgroups name is not used in pam_csession in order to avoid confusion. I find a value of 300 works fine for this, but I use few multithreaded apps, so most users will probably find a value of 1000 is a better choice.  

cpu.max isn't the maximum time that a process has been running for, but rather the amount of time that it's used on the processor (as shown by the top or ps commands). Most processes use very little processor time in normal usage, as they spend most of their time sleeping waiting for input. A process using an hour or more of cpu time is therefore likely to be one that has gotten stuck in an infinite loop, or is otherwise monopolizing the cpu (maybe a cryptominer?).

# EXAMPLES


For all users who are not bob limit maximum threads to 300, maximum cpu time of any process to 2 hours (7200 seconds), and maximum memory used by a process to 10 megabytes. Limit coredumps size to 20 megabytes. Disallow swap memory and give all processes in the cgroup a cpu 'nice' value of 14. In this example the cgroup filesystem is mounted on /dev/cgroup

```
session optional pam_csession.so users=!bob cgroupfs=/dev/cgroup threads.max=300 cpu.nice=14 cpu.max=7200 swap.max=0 proc.mem=10M core.size=20M
```

For user eve allow 200 threads and disallow coredumps, but apply no other limits. The cgroup filesystem mountpoint isn't specified, so will be assumed to be /sys/fs/cgroup.

```
session optional pam_csession.so users=eve threads.max=200 core.size=0
```
