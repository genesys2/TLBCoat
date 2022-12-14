Find results for system under load below.
# TLBCoat gem5 Implementation
​
This repo contains the modified gem5 sources for the TCHES 1/2023 submission _Risky Translations: Securing TLBs against Timing Side Channels_.
We give a brief example how to use it in the following.
​
1. *Dependencies*: For Ubuntu 20.04, run the following:
   ```
   sudo apt install build-essential git m4 scons zlib1g zlib1g-dev \
    libprotobuf-dev protobuf-compiler libprotoc-dev libgoogle-perftools-dev \
    python3-dev python-is-python3 libboost-all-dev pkg-config
   ```
   For older operating systems, see the [official gem5 documentation](https://www.gem5.org/documentation/general_docs/building).
2. *Building gem5:* To build gem5, simply go to the `tlbsec_gem5/` folder and run 
   ```scons build/RISCV/gem5.opt --ignore-style -j[Cores]```
3. *Building m5term:* Go to `tlbsec_gem5/util/term` and run `make`.
4. *Running the Full System Simulation:* To start the full system simulation, go to the `tlbsec_riscv_boot/` folder and run 
   ```
   ../tlbsec_gem5/build/RISCV/gem5.opt ../tlbsec_gem5/configs/example/riscv/fs_linux.py --kernel=./bbl --caches --mem-size=256MB --mem-type=DDR4_2400_8x8 --cpu-type=TimingSimpleCPU --disk-image=./riscv_parsec_disk -n 1
   ```
5. *Connecting to the Terminal:* In a separate terminal window, go to `tlbsec_gem5/util/term` and run 
   ```
   ./m5term 127.0.0.1 3456
   ```
   When the login prompt appears, use user _root_ and password _root_. The benchmarks are located in the `/home/images` folder.
​
## Switch between Set-Associative TLB and TLBCoat

The implementation of the TLB is in `tlbsec_gem5/src/arch/riscv/tlb_cache.[cc/hh]`. You can switch between the set-associative
TLB (not randomized) and the randomized TLB using the `#define SATLB 1` - if SATLB is set to 1, the set-associative TLB is used.
If it is not defined, the randomized TLB is used. Remember to re-build gem5 after changing this. 
​

# TLBCoat Under Load

​We ran the benchmarks in the gem5 simulation environment with additional system load. 
Therefore, we use the same system configuration as in the paper.
Instead of only running a single benchmark on the simulated system, we spawned the blackscholes benchmark in an endless loop to generate system load (we chose blackscholes because it is the first one alphabetically, it would be possible to chosse any other load). 
Then, we started different benchmarks using the simsmall workload and measured the overall TLB miss rate, which is now affected by the TLB usage of the background application. 
We choose the miss rate as a metric since it allows directly comparing the TLB performance. 
Using e.g. the cycle count, it would be harder to actually draw conclusions about the TLB performance since running 
two benchmarks on a single core obviously increases the runtime and the more or less random scheduling decisions can impact
the results severely. 
​
| Benchmark   | SA TLB LRU  | TLBCoat RPLU |
| ----------- | ----------- | ------------ |
| blackscholes| 0.021%    | 0.028%      |
| dedup | 0.046%     | 0.055%      |
| canneal| 3%     | 3.7%      |
| freqmine | 0.21%     | 0.30%    |

The table shows the miss rate for a time-shared system under load for different benchmarks. 
The overall miss rate is similar to the results from the unloaded system evaluated in the paper (Tab. 2).
That is, since most of the benchmarks only rely on few pages that remain cached even with two benchmarks running. 
Moreover, it shows that the miss rate remains similar for set-associative TLBs and TLBcoat. 
The reason for this is, that the re-randomization is done per process by changing the rid and therefore,
a high miss rate in one process does not cause re-randomization in the other process.  


# Functional Simulator
​
The functional simulator is located in `functional/`. It is based on python3 and requires to install the progressbar2 package using 
`pip3 install progressbar2`. By running `python3 tlb.py`, the script generates the figures from the paper (depending on the configuration, this may take some time). The configuration can be changed beginning in line 536 (For the last figure, the configuration must also be changed in line 537). 
​
## Original gem5 Readme
This is the gem5 simulator.
​
The main website can be found at http://www.gem5.org
​
A good starting point is http://www.gem5.org/about, and for
more information about building the simulator and getting started
please see http://www.gem5.org/documentation and
http://www.gem5.org/documentation/learning_gem5/introduction.
​
To build gem5, you will need the following software: g++ or clang,
Python (gem5 links in the Python interpreter), SCons, SWIG, zlib, m4,
and lastly protobuf if you want trace capture and playback
support. Please see http://www.gem5.org/documentation/general_docs/building
for more details concerning the minimum versions of the aforementioned tools.
​
Once you have all dependencies resolved, type 'scons
build/<ARCH>/gem5.opt' where ARCH is one of ARM, NULL, MIPS, POWER, SPARC,
or X86. This will build an optimized version of the gem5 binary (gem5.opt)
for the the specified architecture. See
http://www.gem5.org/documentation/general_docs/building for more details and
options.
​
The basic source release includes these subdirectories:
   - configs: example simulation configuration scripts
   - ext: less-common external packages needed to build gem5
   - src: source code of the gem5 simulator
   - system: source for some optional system software for simulated systems
   - tests: regression tests
   - util: useful utility programs and files
​
To run full-system simulations, you will need compiled system firmware
(console and PALcode for Alpha), kernel binaries and one or more disk
images.
​
If you have questions, please send mail to gem5-users@gem5.org
​
Enjoy using gem5 and please share your modifications and extensions.
​
