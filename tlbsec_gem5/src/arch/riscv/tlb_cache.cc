#include "tlb_cache.hh"
#include "base/trace.hh"

// Miss Threshold
#define MAX_EVICT 64

// Enable set assosciative TLB instead
// #define SATLB 1

namespace RiscvISA {
    RiscVTLBCache::RiscVTLBCache(const RiscVTLBCacheParams &params) :
    SimObject(params)
    {
        // Configure TLB
        ways = 4;
        sets = 16;
        
        // Dummy cpu key
        prince_key = 0x0011223344556677;

        // Stats
        rerand_requests = 0;
        global_page_max = 0;

        cacheData = (TLBMeta**) malloc(sets*sizeof(TLBMeta*));
        

        // Init Cache
        for(uint8_t i=0; i<sets; i++){
            cacheData[i] = (TLBMeta*) malloc(ways * sizeof(TLBMeta));
            for(uint8_t j=0; j<ways; j++){
                cacheData[i][j].valid = false;
                (cacheData[i][j].entry).lruSeq = j+1; // set initial LRU sequence 1->4
            }
        }

        DPRINTF(RiscVTLBCache, "Initilalized TLBCache with %d ways and %d sets (Struct size: %d).\n", ways, sets, sizeof(TLBMeta));
    }

    RiscVTLBCache::~RiscVTLBCache()
    {
        delete this;
    }

    void RiscVTLBCache::randomize(Addr va, uint64_t process_id, uint64_t* set_arr) {
        uint64_t randomization = encrypt(va, prince_key ^ process_id ^ random_id[process_id]);

        for(int i = 0; i < ways; i++) {
            set_arr[i] = (randomization >> (i*4)) & 0xF;
        }

    }

    void RiscVTLBCache::updatePLRUSet(uint32_t set, uint32_t way) {
        // If entry to update is already MRU, then set does not have to be updated
        if ( (cacheData[set][way].entry).lruSeq == 1) return;
        DPRINTF(RiscVTLBCache, "Update PLRU Set %d at way %d: Before %d %d %d %d\n", set, way, (cacheData[set][0].entry).lruSeq, (cacheData[set][1].entry).lruSeq, (cacheData[set][2].entry).lruSeq, (cacheData[set][3].entry).lruSeq);

        // Set entry to MRU
        (cacheData[set][way].entry).lruSeq = 1;

        // Mark entry seen
        uint8_t sawIndex = 0;
        sawIndex ^= (1 << way);

        bool found = false;

        // Search
        for(uint32_t i = 0; i < ways; i++) {
            if ( (sawIndex & (1 << i)) != 0 ) continue;

            if (( cacheData[set][i].entry).lruSeq == 1) {
                ( cacheData[set][i].entry).lruSeq = 2;
                sawIndex ^= (1 << i);
                found = true;
                break;
            }
        }

        if (found == false) assert(false); // should not happen
        found = false;

        for(uint32_t i = 0; i < ways; i++) {
            if ( (sawIndex & (1 << i)) != 0 ) continue;
            
            if (( cacheData[set][i].entry).lruSeq == 2) {
                ( cacheData[set][i].entry).lruSeq = 3;
                sawIndex ^= (1 << i);
                found = true;
                break;
            }
        }

        if (found == false) {
            DPRINTF(RiscVTLBCache, "Update PLRU Set %d at way %d: After %d %d %d %d (early)\n", set, way, (cacheData[set][0].entry).lruSeq, (cacheData[set][1].entry).lruSeq, (cacheData[set][2].entry).lruSeq, (cacheData[set][3].entry).lruSeq);
            return;
        }

        for(uint32_t i = 0; i < ways; i++) {
            if ( (sawIndex & (1 << i)) != 0 ) continue;
            
            if (( cacheData[set][i].entry).lruSeq == 3) {
                ( cacheData[set][i].entry).lruSeq = 4;
                break;
            }
        }
        DPRINTF(RiscVTLBCache, "Update PLRU Set %d at way %d: After %d %d %d %d\n", set, way, (cacheData[set][0].entry).lruSeq, (cacheData[set][1].entry).lruSeq, (cacheData[set][2].entry).lruSeq, (cacheData[set][3].entry).lruSeq);
    }

    TlbEntry* RiscVTLBCache::lookup(Addr va, uint16_t asid) {
        DPRINTF(RiscVTLBCache, "(Lookup) Start Lookup for %x (%x)\n", va, ((va >> 12)<<12));

        // Get rid of last 12 bits (4KB page)
        va = va >> 12;
        va = va << 12;
        uint64_t sets[ways] = {0};

        #ifndef SATLB
        randomize(va,(uint64_t) asid,sets);
        #else
        sets[0] = (va >> 12) % 16;
        sets[1] = (va >> 12) % 16;
        sets[2] = (va >> 12) % 16;
        sets[3] = (va >> 12) % 16;
        #endif

        for(int i = 0; i < ways; i++) {
            DPRINTF(RiscVTLBCache, "(Lookup 4KB) Trying %x in way %d, set %d\n", va, i, sets[i]);
            if(cacheData[ sets[i] ][i].valid == true){
                if ((cacheData[ sets[i] ][i].entry).logBytes != 12){
                    continue;
                }
                if(((cacheData[ sets[i] ][i].entry).vaddr) == va && ((cacheData[ sets[i] ][i].entry).asid) == asid) {
                    DPRINTF(RiscVTLBCache, "(Lookup 4KB) Found %x in set %d, way %d\n",va, sets[i] , i);
                    updatePLRUSet(sets[i],i);
                    return &(cacheData[ sets[i] ][i].entry);
                }
            } 
        }

        // Get rid of last 21 bits (large page)
        va = va >> 21;
        va = va << 21;

        #ifndef SATLB
        randomize(va,(uint64_t) asid,sets);
        #else
        sets[0] = (va >> 21) % 16;
        sets[1] = (va >> 21) % 16;
        sets[2] = (va >> 21) % 16;
        sets[3] = (va >> 21) % 16;
        #endif

        for(int i = 0; i < ways; i++) {
            DPRINTF(RiscVTLBCache, "(Lookup Huge) Trying %x in way %d, set %d\n", va, i, sets[i]);
            if(cacheData[ sets[i] ][i].valid == true){
                if ((cacheData[ sets[i] ][i].entry).logBytes != 21){
                    if((cacheData[ sets[i] ][i].entry).logBytes != 12){
                        DPRINTF(RiscVTLBCache, "Size is %d\n", (cacheData[ sets[i] ][i].entry).logBytes);
                        assert(false);
                    }
                    continue;
                }
                if(((cacheData[ sets[i] ][i].entry).vaddr) == va && ((cacheData[ sets[i] ][i].entry).asid) == asid) {
                    DPRINTF(RiscVTLBCache, "(Lookup Huge) Found %x in set %d, way %d\n",va, sets[i] , i);
                    updatePLRUSet(sets[i],i);
                    return &(cacheData[ sets[i] ][i].entry);
                }
            }  
        }

        return NULL;
    }

    TlbEntry* RiscVTLBCache::insert(Addr vpn, TlbEntry entry){

        // Get rid of last x bits (large or small page)
        uint64_t addr = vpn >> entry.logBytes;
        addr = addr << entry.logBytes;
        DPRINTF(RiscVTLBCache, "(Insert) Start inserting %x with asid %x (%x)\n", vpn,entry.asid,addr);

        uint64_t sets[ways] = {0};
        #ifndef SATLB
        randomize(addr, (uint64_t) entry.asid, sets);
        #else
        sets[0] = (vpn >> entry.logBytes) % 16;
        sets[1] = (vpn >> entry.logBytes) % 16;
        sets[2] = (vpn >> entry.logBytes) % 16;
        sets[3] = (vpn >> entry.logBytes) % 16;
        #endif

        // Look if we find an invalid entry already
        int32_t wayIndex = -1;
        for(int i = 0; i < ways; i++) {
            if(cacheData[ sets[i] ][i].valid == false) {
                wayIndex = i;
                break;
            }
        }

        #ifndef SATLB
        // If not, rerandomize and check again
        if (wayIndex == -1) {
            evict_cnt[entry.asid]++;
            if(evict_cnt[entry.asid] == MAX_EVICT) {
                rerand_requests++;
                evict_cnt[entry.asid] = 0;
                random_id[entry.asid]++; // Worst case rid selection (just incrementing from 0)
                randomize(addr, (uint64_t) entry.asid, sets);
                for(int i = 0; i < ways; i++) {
                    if(cacheData[ sets[i] ][i].valid == false) {
                        wayIndex = i;
                        break;
                    }
                }
            }
        }
        #endif

        // We will did not find any invalid entry. Evict LRU.
        if (wayIndex == -1) {
            wayIndex = evict(sets);
        };

        uint32_t temp_lru = (cacheData[ sets[wayIndex] ][wayIndex].entry).lruSeq;

        cacheData[ sets[wayIndex] ][wayIndex].entry = entry;
        cacheData[ sets[wayIndex] ][wayIndex].valid = true;

        (cacheData[ sets[wayIndex] ][wayIndex].entry).lruSeq = temp_lru;
        updatePLRUSet(sets[wayIndex], wayIndex);

        DPRINTF(RiscVTLBCache, "(Insert) Inserted %x in set %d and way %d\n",vpn, sets[wayIndex] , wayIndex);
        return &(cacheData[ sets[wayIndex] ][wayIndex].entry);
    }

    uint8_t RiscVTLBCache::evict(uint64_t* set_arr){
        // Evict if no free index found
        uint8_t wayIndex = 0;
        for(int i = 1; i < ways; i++) {
            if(cacheData[ set_arr[i] ][i].valid == true && (cacheData[ set_arr[i] ][i].entry).lruSeq > (cacheData[ set_arr[wayIndex] ][wayIndex].entry).lruSeq) {
                wayIndex = i;
            }
        }
        DPRINTF(RiscVTLBCache, "(Evict) Evicted way %d in set %d\n",wayIndex,set_arr[wayIndex]);
        cacheData[ set_arr[wayIndex] ][wayIndex].valid = false;
        return wayIndex;
    }

    void RiscVTLBCache::flushAll(){
        rerand_requests++;
        for(int i = 0; i < (1<<16); i++) {
            random_id[i]++;
            evict_cnt[i] = 0;
        }
        for(uint8_t i=0; i<sets; i++){
            for(uint8_t j=0; j<ways; j++){
                cacheData[i][j].valid = false;
            }
        }
    }

    void RiscVTLBCache::demapPage(Addr va, uint64_t asn){
        DPRINTF(RiscVTLBCache, "(Demap) Starting demapping of %x\n",va); 
        // Get rid of last 12 bits (4KB page)   
        va = va >> 12;
        va = va << 12;

        uint64_t sets[ways] = {0};

        #ifndef SATLB
        randomize(va,asn,sets);
        #else
        sets[0] = (va >> 12) % 16;
        sets[1] = (va >> 12) % 16;
        sets[2] = (va >> 12) % 16;
        sets[3] = (va >> 12) % 16;
        #endif

        for(int i = 0; i < ways; i++) {
            if(cacheData[ sets[i] ][i].valid == true){
                if ((cacheData[ sets[i] ][i].entry).logBytes != 12){
                    continue;
                }

                if(((cacheData[ sets[i] ][i].entry).vaddr) == va && ((cacheData[ sets[i] ][i].entry).asid) == ( (uint16_t) asn)) {
                    DPRINTF(RiscVTLBCache, "(Demap) Found %x in set %d, way %d\n",va,sets[i],i);
                    cacheData[sets[i]][i].valid = false;
                    return;
                }
            }  
        }

        // Get rid of last 21 bits (large page)
        va = va >> 21;
        va = va << 21;
        
        #ifndef SATLB
        randomize(va,asn,sets);
        #else
        sets[0] = (va >> 21) % 16;
        sets[1] = (va >> 21) % 16;
        sets[2] = (va >> 21) % 16;
        sets[3] = (va >> 21) % 16;
        #endif 


        for(int i = 0; i < ways; i++) {
            if(cacheData[ sets[i] ][i].valid == true){
                if ((cacheData[ sets[i] ][i].entry).logBytes != 21){
                    if((cacheData[ sets[i] ][i].entry).logBytes != 12){
                        DPRINTF(RiscVTLBCache, "Size is %d\n", (cacheData[ sets[i] ][i].entry).logBytes);
                        assert(false);
                    }
                    continue;
                }

                if(((cacheData[ sets[i] ][i].entry).vaddr) == va && ((cacheData[ sets[i] ][i].entry).asid) == ( (uint16_t) asn)) {
                    DPRINTF(RiscVTLBCache, "(Demap Huge) Found %x in set %d, way %d\n",va,sets[i],i);
                    cacheData[ sets[i] ][i].valid = false;
                    return;
                }
            }  
        }
    }

    void RiscVTLBCache::demapPageComplex(Addr va, uint64_t asn) {
         asn &= 0xFFFF;
         for(uint8_t i=0; i<sets; i++){
            for(uint8_t j=0; j<ways; j++){
                Addr mask = ~( (cacheData[i][j].entry).size() - 1);
                if ((va == 0 || (va & mask) == (cacheData[i][j].entry).vaddr) && (asn == 0 || (cacheData[i][j].entry).asid == asn)) {
                    cacheData[i][j].valid = false;
                }
            }
        }
    }

    uint64_t RiscVTLBCache::getRerandRequestCount() {
        return rerand_requests;
    }
}