'''
Authors:        ----
Date:           01.10.2021
Used for the evaluation in "Risky Translations: Securing TLBs againstTiming Side-Channels"

This software replicates the storage- and replacement behavior of a randomized set-associative cache / TLB. 
The implementation is not designed to evaluate performacne or replicate a realistic input-ouput behavior of 
caches/TLBs. It is designed to gain maximum insight to the cache/TLB internals, i.e. by making visible 
which exact entries are replaced on a miss access. 
'''

import random
import hashlib
import uuid
from random import shuffle
import progressbar
from datetime import datetime
import matplotlib.pyplot as plt
import multiprocessing

'''
A CacheEntry stores the address and data used for the replacement policy. 
'''
class CacheEntry:
    def __init__(self, data, address, replacement_info):
        self.replacement_info = replacement_info
        self.data = data
        self.address = address

    def get_replacement_info(self):
        return self.replacement_info

    def inc_replacement_info(self):
        self.replacement_info += 1

    def touch_block(self, replacement_info):
        self.replacement_info = replacement_info

    def get_address(self):
        return self.address

'''
The Cache class holds the storage object that representes the current state of the cache. 
New entries can be inserted using the insert() funciton.
'''
class Cache:
    '''
        Create a Cache object with ways * 2**idx_width entries. The replacement policy can 
        be switched between RAND and LRU-
    '''
    def __init__(self, ways, idx_width, replacement_policy = "RAND"):
        if ways & ways-1 != 0 or ways == 0:
            print("Warining! Parameter ways is not a power of two (unusual choice, might be an error?)")

        self.ways = ways
        self.lines = 2**idx_width
        self.idx_width = idx_width
        self.idx_mask = (2**idx_width)-1
        self.replacement_policy = replacement_policy
        if self.replacement_policy == "LRU":
            self.invld_entry = CacheEntry("", 0, datetime.now())
        elif self.replacement_policy == "RPLRU":
            self.invld_entry = CacheEntry("", 0, 0)
        else:
            self.invld_entry = CacheEntry("", self.ways, None)

        # initialize empty storage
        self.storage = [[self.invld_entry] * ways for _ in range(self.lines)] # Initialize with invalid entries.

    '''
        Prints the entire cache content.
        Input:  None
        Output: None
    '''
    def print_cache(self):
        i = 0
        for cset in self.storage:
            for entry in cset:
                print(f"{i}: {entry.address}", end="")
            print("")
            i+=1


    '''
        Input:  Address (Int)
        Output: A list of length w with the candidate index of the address in each way.
    '''
    def get_index(self, address):
        candidates = []
        for i in range(self.ways):
            candidates.append(int(hashlib.sha1((str(address)+str(i)).encode()).hexdigest(), 16) & (self.idx_mask)) # sha1 is relatively fast
        return candidates

    '''
        Input:  A list of indices
        Output: The index of an unused entry, -1 if none exist.
    '''
    def is_set_full(self, indices):
        for way in range(self.ways):
            if self.storage[indices[way]][way] == self.invld_entry:
                return way
        return -1

    '''
        Input:  A list of length w containing candidate indices
                Address (Int)
        Output: Returns the CacheEntry if the address was cached, otherwise invalid_entry
    '''
    def is_hit(self, indices, address):
        for i in range(self.ways):
            if self.storage[indices[i]][i].get_address() == address:
                return (indices[i], i), self.storage[indices[i]][i]
        return (0, 0), self.invld_entry

    '''
        Inserts an address to the cache if it is not contained already.
        Input:  Address (Int)
        Output: None            - if the access resulted in a hit
                victim entry    - if the access resulted in a miss 
                                (the victim entry is selected by the replacement policy)
    '''
    def insert(self, address):
        indices = self.get_index(address)
        victim = self.invld_entry

        hit_position, entry = self.is_hit(indices, address)

        # Check if the address is already cached
        if entry != self.invld_entry:
            if self.replacement_policy == "LRU":
                entry.touch_block(datetime.now())
            elif self.replacement_policy == "RPLRU":
                self.update_plru_state(hit_position[0], hit_position[1])
            return None
        else:
            # Relacement Policies
            if self.replacement_policy == "RAND":
                way_id = random.randint(0, self.ways-1)
                victim = self.storage[indices[way_id]][way_id]
                self.storage[indices[way_id]][way_id] = CacheEntry("", address, None)
            elif self.replacement_policy == "LRU":
                oldest_ts = self.storage[indices[0]][0].get_replacement_info()
                way_id = 0
                for way in range(1, self.ways):
                    if self.storage[indices[way]][way].get_replacement_info() < oldest_ts:
                        oldest_ts =  self.storage[indices[way]][way].get_replacement_info()
                        way_id = way
                victim = self.storage[indices[way_id]][way_id]
                self.storage[indices[way_id]][way_id] = CacheEntry("", address, datetime.now())
            elif self.replacement_policy == "RPLRU":
                entries = []
                for way in range(0, self.ways):
                    entries.append((way, self.storage[indices[way]][way].get_replacement_info()))
                entries = maxes(entries, key=lambda x: x[1])
                way_id = random.choice(entries)[0]
                victim = self.storage[indices[way_id]][way_id]
                self.update_plru_state(indices[way_id], way_id)
                self.storage[indices[way_id]][way_id] = CacheEntry("", address, 0)
            else:
                print(f"Invalid Replacement Policy! {self.replacement_policy}")
                exit()
        return victim

    def update_plru_state(self, index, accessed_way):
        lru_state = self.storage[index][accessed_way].get_replacement_info()
        #print(f"### Replacement Block {index} ###")
        for way in range(0, self.ways):
            #print(self.storage[index][way].get_replacement_info(), end='')
            if self.storage[index][way].get_replacement_info() <= lru_state:
                self.storage[index][way].inc_replacement_info()
        self.storage[index][accessed_way].touch_block(0)
        #print("")


    '''
        Input:  A set of addresses that might be an eviction set and are already cached
        Output: A victim address

        Returns true if the victim address would evict one of the addresses from
        the eviction set WITHOUT actually accessing the victim address. This is not
        possible in a normal cache/TLB. Otherwise, returns false.
    '''
    def would_evict_attacker_address(self, attacker_addresses, address):
        indices = self.get_index(address)
        victim = self.invld_entry

        hit_entry = self.is_hit(indices, address)[1]

        if hit_entry != self.invld_entry:
            hit_entry.touch_block(datetime.now())
            print("Something went wrong! Victim entry was a hit...")
            pass
        else:
            if self.replacement_policy == "RAND":
                way_id = random.randint(0, self.ways-1)
            elif self.replacement_policy == "LRU":
                oldest_ts = self.storage[indices[0]][0].get_replacement_info()
                way_id = 0
                for way in range(self.ways):
                    if self.storage[indices[way]][way].get_replacement_info() < oldest_ts:
                        oldest_ts =  self.storage[indices[way]][way].get_replacement_info()
                        way_id = way
            elif self.replacement_policy == "RPLRU":
                entries = []
                for way in range(0, self.ways):
                    entries.append((way, self.storage[indices[way]][way].get_replacement_info()))
                entries = maxes(entries, key=lambda x: x[1])
                way_id = random.choice(entries)[0]
            else:
                print("Invalid Replacement Policy!")
                exit()
            victim = self.storage[indices[way_id]][way_id]
            #self.storage[indices[way_id]][way_id] = CacheEntry("", address, datetime.now())
        if victim.address in attacker_addresses:
            return True
        else: 
            return False

############## Helper Functions
'''
    Returns the average value of a list if the list is not empty.
'''
def avg(lst):
    return sum(lst)/len(lst) if len(lst) != 0 else 0

'''
    Borrowed from Stackoverflow 
    https://stackoverflow.com/questions/10823227/how-to-get-all-the-maximums-max-function
'''
def maxes(a, key=None):
    if key is None:
        key = lambda x: x
    m, max_list = key(a[0]), []
    for s in a:
        k = key(s)
        if k > m:
            m, max_list = k, [s]
        elif k == m:
            max_list.append(s)
    return max_list

'''
    Helper function that gerneates num random addresses
'''
def generate_random_addresses(num):
    addr_list = []
    for i in range(num):
        addr_list.append(uuid.uuid4().int & (1<<64)-1)
    return addr_list


'''
    Helper function that prints the candidates for the addresses in addrs
'''
def check_address_list(c, addrs):
    for addr in addrs:
        print(f"Candidates for {addr}:\t {c.get_index(addr)}")


'''
    Simulate the access to the victim. 
'''
def trigger_victim(c, target, noise_accesses):
    for _ in range(noise_accesses):
        c.insert(uuid.uuid4().int & (1<<64)-1)
    c.insert(target)

'''
    Returns true if an eviction set G collides in all ways with the target address
'''
def check_eviction_set(c, target, G):
    return is_valid_eviction_set(c.get_index(target), [c.get_index(addr) for addr in G])

'''
    Recursive subrotine to check whether the eviction set is complete.
'''
def is_valid_eviction_set(victim_candidates, ev_candidates_list):
    if all(x == -1 for x in victim_candidates):
        return True
    for n, attacker_candidates in enumerate(ev_candidates_list):
        for i, _ in enumerate(attacker_candidates):
            if victim_candidates[i] == attacker_candidates[i]:
                return is_valid_eviction_set(victim_candidates[:i] + [-1] + victim_candidates[i+1:], ev_candidates_list[:n] + ev_candidates_list[n+1:])
    return False

'''
    Helper function that accesses all addresses from adrs and counts the misses.
    Input:  List of addresses
    Output: The amount of misses
'''
def access_and_count_misses(c, adrs):
    conflicts = []
    for addr in adrs:
        if c.insert(addr) != None:
            conflicts.append(addr)
    return conflicts


### Attack simulations and graph construction

'''
    This function was used to gernate Figure 5 from the paper
'''
def boxplot_eviction():
    result = []
    max_val = 50000

    for replacement_policy in ["RPLRU", "LRU", "RAND"]:
        c = Cache(4, 4, replacement_policy=replacement_policy)
        lst = []
        with progressbar.ProgressBar(max_value=max_val) as bar:
            for x in range(max_val):
                ctr = 0
                target = uuid.uuid4().int & (1<<64)-1
                c.insert(target)
                victim = c.invld_entry

                while(victim.address != target):
                    victim = c.insert(uuid.uuid4().int & (1<<64)-1)
                    ctr += 1
                lst.append(ctr)
                bar.update(x)
        print(f"Result: {sum(lst) / len(lst) }")
        print(f"Min: {min(lst)}")
        result.append(lst)

        width_height_1 = (27, 1.5)
        fig = plt.figure(figsize=width_height_1)
        fig.subplots_adjust(bottom=0.3)
        plt.rcParams.update({'font.size': 18})

    plt.boxplot(result, vert=False, widths=.16, positions=[.1, .3, .5])
    plt.yticks([.1, .3, .5], ['RPLRU', 'LRU', 'RAND'])
    axes = plt.gca()
    axes.set_aspect('auto')
    axes.set_ylim([0,.6])
    plt.gca().set_xlim(left=0)
    plt.savefig('replacements.png')

'''
    This was used to generate Figure 7. Runs one step of prime and prune and counts the misses.
'''
def prime_and_prune_once(configs, iterations = 10000):
    result = {}

    for name, c in configs.items():
        config_result = [{"success": 0, "fail": 0, "misses": 0}  for _ in range(c.ways*2**(c.idx_width))]
        with progressbar.ProgressBar(max_value=c.ways*2**c.idx_width) as bar:
            for set_size in range(c.ways*2**c.idx_width):
                for _ in range(iterations):
                    target = uuid.uuid4().int & (1<<64)-1
                    attacker_adrs = []
                    misses = 0
                    for y in range(set_size):
                        addr = uuid.uuid4().int & (1<<64)-1
                        attacker_adrs.append(addr)
                        c.insert(addr)
                        misses += 1
                    
                    fail_cnt = 0
                    while True:
                        conflicts = access_and_count_misses(c, attacker_adrs)
                        if len(conflicts) == 0:
                            break
                        misses += len(conflicts)
                        fail_cnt += 1
                        if fail_cnt > 3:
                            if len(conflicts) > 10:
                                attacker_adrs.remove(conflicts[0])
                                attacker_adrs.remove(conflicts[1])
                                attacker_adrs.remove(conflicts[2])
                                attacker_adrs.remove(conflicts[3])
                                attacker_adrs.remove(conflicts[4])
                                attacker_adrs.remove(conflicts[5])
                            #print(f"Failed Attack! Cannot Prune! {len(conflicts)},{set_size}")
                            else:
                                attacker_adrs.remove(conflicts[0])

                    config_result[set_size]["misses"] += misses       
                    if c.would_evict_attacker_address(attacker_adrs, target):
                        config_result[set_size]["success"] += 1
                    else:
                        config_result[set_size]["fail"] += 1
                bar.update(set_size)
            #print(lst)
        avgs = []
        misses = []
        for e in config_result:
            avgs.append(round(e["success"]/(e["success"]+e["fail"]),3) if (e["success"]+e["fail"]) != 0 else None)
            misses.append(e["misses"]/(e["success"]+e["fail"]))
        print(avgs)
        fig, ax1 = plt.subplots()
        
        ax1.set_xlim(0,c.ways*2**c.idx_width)
        ax1.plot(avgs,  label=name, color="tab:red")
        ax1.tick_params(axis='y', colors='tab:red')
        ax1.set_xlabel('Initial Priming Set Size', fontsize=15)
        ax1.set_ylabel('Success Probability', color="tab:red", fontsize=15)
        ax1.set_ylim(0,1)
        ax2 = ax1.twinx()
        ax2.plot(misses, label=name, color="tab:blue")
        ax2.tick_params(axis='y', colors='tab:blue')
        ax2.set_ylim(0,None)
        ax2.set_ylabel('Avg. #Misses', color="tab:blue", fontsize=15)
        
        for label in (ax1.get_xticklabels() + ax1.get_yticklabels()+ ax2.get_yticklabels()):
	        label.set_fontsize(15)
        plt.gcf().subplots_adjust(bottom=0.12, right=0.87)
        plt.savefig(f'misses_{name}.png')
        result[name] = avgs




'''
    This function was used to create Figure 7 in the paper. 
    The prime+prune+probe attack is implemented in a way that minimizes the
    cache / TLB misses occuring. 

    Returns the number of misses as well as the success rate
'''
def prime_prune_probe_profiling(c, iterations=150, set_size=50):
    target = uuid.uuid4().int & (1<<64)-1
    result = []
    with progressbar.ProgressBar(max_value=iterations) as bar:
        for x in range(iterations):
            attacker_adrs = [] # Prime Addresses

            ## Build the first prime set
            for _ in range(set_size):
                addr = uuid.uuid4().int & (1<<64)-1
                attacker_adrs.append(addr)

            misses = 0
            G = [] # Generalized Eviction Set

            while True:
                while len(attacker_adrs) < set_size:
                    addr = uuid.uuid4().int & (1<<64)-1
                    attacker_adrs.append(addr)
                
                # Prime Step
                for addr in attacker_adrs:
                    if c.insert(addr) != None: # If the access is not a hit
                        misses += 1
                
                # Prune Step
                # We implement a fail counter that removes addresses from the prime set if prune fails too many times
                fail_cnt = 0
                while True:
                        conflicts = access_and_count_misses(c, attacker_adrs)
                        if len(conflicts) == 0:
                            break
                        misses += len(conflicts)
                        fail_cnt += 1
                        if fail_cnt > 3:
                            # This indicates that the pime set is way to big, accelerate the attack by removing more addresses
                            if len(conflicts) > 10:
                                attacker_adrs.remove(conflicts[0])
                                attacker_adrs.remove(conflicts[1])
                                attacker_adrs.remove(conflicts[2])
                                attacker_adrs.remove(conflicts[3])
                                attacker_adrs.remove(conflicts[4])
                                attacker_adrs.remove(conflicts[5])
                            else:
                                attacker_adrs.remove(conflicts[0])
                # Victim Access    
                trigger_victim(c, target, 0)
                victim_removed = False

                # Probe Step
                for addr in attacker_adrs:
                    res = c.insert(addr)
                    if res != None: # insert resulted in a miss
                        G.append(addr) # Add addr to the eviction set
                        attacker_adrs.remove(addr) # we don't want to observe the same address twice
                        if res.get_address() == target:
                            victim_removed = True
                        break
                
                if misses > 2 * c.ways*c.lines:
                    break
                ## Evict the victim entry so we can start the next round
                ## We give the attacker the information when the victim is successfully removed. This information is usually not accessible by the attacker.
                ## To minimize the misses during this phase, we start by accessing the addresses from the attacker which mostly result in hits.
                
                # Start by accessing all knwon addresses that conflict with the victim
                for addr in G:
                    res = c.insert(addr)
                    if res != None: # A miss occured
                        misses +=1
                        if res.get_address() == target: # Victim was evicted
                            victim_removed = True
                            break

                for addr in attacker_adrs:
                    if victim_removed:
                        break
                    res = c.insert(addr)
                    if res != None: # A miss occured
                        misses +=1
                        if res.get_address() == target: # Victim was evicted
                            victim_removed = True
                # The prime set was not enough to evict the target, we add one address to the attacker adrs and re-access all others 
                while not victim_removed:
                    #print(victim_removed)
                    new_addr = uuid.uuid4().int & (1<<64)-1
                    attacker_adrs.append(new_addr)
                    res = c.insert(new_addr)
                    if res != None: # A miss occured
                        misses +=1
                        if res.get_address() == target: # Victim was evicted
                            victim_removed = True
                            break
                    for addr in attacker_adrs:
                        res = c.insert(addr)
                        if res != None: # A miss occured
                            misses +=1
                            if res.get_address() == target: # Victim was evicted
                                victim_removed = True
                                break
                
                # Make sure attacker_adrs is not larger than set_size
                while len(attacker_adrs) > set_size:
                    attacker_adrs.pop(0)
                
                if check_eviction_set(c, target, G):
                    result.append(misses)
                    break
                elif misses > 2 * c.ways*c.lines: # abort if misses are very high (we only care for the minimum anyway)...
                    break
            
            bar.update(x)
    return result, len(list(filter(lambda x: x <= c.ways*2**c.idx_width, result)))#/iterations

def ppp_wrapper(set_size):#
    print(f"Starting {set_size}")
    c = Cache(4, 4, replacement_policy="RPLRU")
    return prime_prune_probe_profiling(c, iterations=4000, set_size=set_size)
### Main

configs = {}
configs["w=4, N=64"]=Cache(4, 4, replacement_policy="RPLRU")
#configs["w=4, N=128"]=Cache(4, 5, replacement_policy="LRU")
#configs["w=8, N=64"]=Cache(8, 3, replacement_policy="LRU")
#configs["w=8, N=128"]=Cache(8, 4, replacement_policy="LRU")
#configs["w=8, N=1024"]= Cache(8, 7, replacement_policy="RPLRU")

# Figure 5
#boxplot_eviction()
#exit(1)
# Figure 7
#prime_and_prune_once(configs, iterations=5000)
# exit()

# Figure 8 (but with 15000 runs instead of 100000)
lower_limit = 10
for name, c in configs.items():
    res = [float("nan")]*lower_limit
    success_res = [0]*lower_limit
    pool = multiprocessing.Pool(16)
    misses, success_rate = list(zip(*pool.map(ppp_wrapper, range(lower_limit, c.ways * c.lines))))
    #print(misses)
    for l in misses:
        res.append(min(filter(lambda x: x != float("nan"), l), default=float("nan")))
    success_res.extend(success_rate)
    #exit()
    #for set_size in range(25, c.ways * c.lines):
    #    print(f"Step {set_size}")
    #    misses, success_rate = ppp_wrapper(set_size=set_size) #prime_prune_probe_profiling(c, iterations=15000, set_size=set_size)
    #    res.append(min(filter(lambda x: x != float("nan"), misses), default=float("nan")))
    #    success_res.append(success_rate)

    fig, ax = plt.subplots()
    ax.tick_params(axis='y', colors='tab:blue')
    ax.set_xlim(lower_limit ,c.ways*2**c.idx_width)
    ax.set_xlabel('Initial Priming Set Size', fontsize=15)
    fig.subplots_adjust(right=0.8)
    plt.axhline(y = c.ways*2**c.idx_width, color = 'r', linestyle = '-')
    ax.plot(res, label=name)
    
    ax.set_ylabel('Min. #Misses for Profiling', color="tab:blue", fontsize=15)

    ax2 = ax.twinx()
    ax2.tick_params(axis='y', colors='tab:green')
    ax2.plot(success_res, label=name, color="tab:green")
    ax2.set_ylim(0,40)
    ax2.set_ylabel(f'Runs with ≤ {c.ways*2**c.idx_width} misses', color="tab:green", fontsize=15)
    ax.set_ylim(0,c.ways*2**c.idx_width*3)

    ticks = list((ax.get_yticks())) + [c.ways*2**c.idx_width]
    ticks.remove(64)
    ax.set_yticks(ticks)
    plt.savefig(f'ppp_profiling_w={c.ways}_N={c.ways*2**c.idx_width}.png')

