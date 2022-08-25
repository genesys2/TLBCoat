#include "tlb_cache.hh"
#include "base/trace.hh"
#define MAX_EVICT 64

namespace X86ISA {

TLBCache::TLBCache(const TLBCacheParams &p) : 
SimObject(p), ways(p.ways), sets(p.sets)
{
    ways = p.ways;
    sets = p.sets;
    
    prince_key = 0x0011223344556677;
    random_id = 0;
    evict_cnt = 0;
    rerand_requests = 0;
    global_page_max = 0;

    cacheData = (TLBMeta**) malloc(sets*sizeof(TLBMeta*));
    

    for(uint8_t i=0; i<sets; i++){
        cacheData[i] = (TLBMeta*) malloc(ways * sizeof(TLBMeta));
        for(uint8_t j=0; j<ways; j++){
            cacheData[i][j].valid = false;
        }
    }
    DPRINTF(TLBCache, "Initilalized TLBCache with %d ways and %d sets (Struct size: %d).\n", ways, sets, sizeof(TLBMeta));
}

TLBCache::~TLBCache()
{
    delete this;
}

void TLBCache::randomize(Addr va, uint64_t process_id, uint64_t* set_arr) {
    for(int i = 0; i < ways; i++) {
        set_arr[i] = encrypt(va, prince_key ^ process_id ^ random_id ^ i) % sets;
    }
}

TlbEntry*
TLBCache::lookup(Addr va){
    //VPN||PageOffset    
    //DPRINTF(TLBCache, "(Lookup) Lookup %x in set %d\n",va, (va >> 12) % sets);
    DPRINTF(TLBCache, "(Lookup) Start Lookup for %x\n", va);

    va = va >> 12;
    va = va << 12;
    // NEW
    uint64_t sets[ways] = {0};
    randomize(va,0,sets);
    for(int i = 0; i < ways; i++) {
        DPRINTF(TLBCache, "(Lookup 4KB) Trying %x in way %d, set %d\n", va, i, sets[i]);
        if(cacheData[ sets[i] ][i].valid == true){
            if ((cacheData[ sets[i] ][i].entry).logBytes != 12){
                continue;
            }
            //DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[ sets[i] ][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Lookup 4KB) Found %x in set %d, way %d\nEntry: %s",va, sets[i] , i, (cacheData[ sets[i] ][i].entry).print());
                return &(cacheData[ sets[i] ][i].entry);
            }
        } 
    }
    /* OLD
    uint64_t set = (va >> 12) % sets;
    
    for(int i = 0; i < ways; i++) {
        if(cacheData[set][i].valid == true){
            if ((cacheData[set][i].entry).logBytes != 12){
                continue;
            }
            //DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[set][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Lookup) Found %x in set %d, way %d\nEntry: %s",va, set, i, (cacheData[set][i].entry).print());
                return &(cacheData[set][i].entry);
            }
        }  
    }
    */

    va = va >> 21;
    va = va << 21;
    // NEW
    randomize(va,0,sets);
    for(int i = 0; i < ways; i++) {
        DPRINTF(TLBCache, "(Lookup Huge) Trying %x in way %d, set %d\n", va, i, sets[i]);
        if(cacheData[ sets[i] ][i].valid == true){
            if ((cacheData[ sets[i] ][i].entry).logBytes != 21){
                if((cacheData[ sets[i] ][i].entry).logBytes != 12){
                    DPRINTF(TLBCache, "Size is %d\n", (cacheData[ sets[i] ][i].entry).logBytes);
                    assert(false);
                }
                continue;
            }
            //DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[ sets[i] ][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Lookup Huge) Found %x in set %d, way %d\nEntry: %s",va, sets[i] , i, (cacheData[ sets[i] ][i].entry).print());
                return &(cacheData[ sets[i] ][i].entry);
            }
        }  
    }

    /* OLD
    set = (va >> 21) % sets;
    //DPRINTF(TLBCache, "(Lookup Hugepage) Lookup %x in set %d\n",va, set);
    for(int i = 0; i < ways; i++) {
        if(cacheData[set][i].valid == true){
            if ((cacheData[set][i].entry).logBytes != 21){
                if((cacheData[set][i].entry).logBytes != 12){
                    DPRINTF(TLBCache, "Size is %d\n", (cacheData[set][i].entry).logBytes);
                    assert(false);
                }
                continue;
            }
            //DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[set][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Lookup Huge) Found %x in set %d, way %d\nEntry: %s",va, set, i, (cacheData[set][i].entry).print());
                return &(cacheData[set][i].entry);
            }
        }  
    }
    */

    return NULL;
}

void TLBCache::flushNonGlobal(){
    countGlobalPages();
    evict_cnt = 0;
    DPRINTF(TLBCache, "Invalidating all non global entries.\n");
    for(int i = 0; i < sets; i++) {
        for(int j = 0; j < ways; j++) {
            if(cacheData[i][j].valid == true && !((cacheData[i][j].entry).global) ) cacheData[i][j].valid = false;
        }
    }
    random_id++;
}

uint8_t TLBCache::evict(uint64_t* set_arr){
    // Evict if no free index found
    uint8_t wayIndex = 0;
    for(int i = 1; i < ways; i++) {
        if(cacheData[ set_arr[i] ][i].valid == true && (cacheData[ set_arr[i] ][i].entry).lruSeq < (cacheData[ set_arr[wayIndex] ][wayIndex].entry).lruSeq) {
            wayIndex = i;
        }
    }
    DPRINTF(TLBCache, "(Evict) Evicted way %d in set %d\n",wayIndex,set_arr[wayIndex]);
    cacheData[ set_arr[wayIndex] ][wayIndex].valid = false;
    return wayIndex;
}

void TLBCache::demapPage(Addr va, uint64_t asn){

    DPRINTF(TLBCache, "(Demap) Starting demapping of %x\n",va);    
    va = va >> 12;
    va = va << 12;

    uint64_t sets[ways] = {0};
    randomize(va,0,sets);

    for(int i = 0; i < ways; i++) {
        if(cacheData[ sets[i] ][i].valid == true){
             if ((cacheData[ sets[i] ][i].entry).logBytes != 12){
                continue;
            }

            if(((cacheData[ sets[i] ][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Demap) Found %x in set %d, way %d\n",va,sets[i],i);
                cacheData[sets[i]][i].valid = false;
                return;
            }
        }  
    }

    /* OLD
    uint64_t set = (va >> 12) % sets;
    DPRINTF(TLBCache, "(DEMAP) Lookup %x in set %d\n",va, set);
    for(int i = 0; i < ways; i++) {
        if(cacheData[set][i].valid == true){
            DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[set][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(DEMAP) Found %x in set %d, way %d\n",va,set,i);
                cacheData[set][i].valid = false;
                return;
            }
        }  
    }
    */

    va = va >> 21;
    va = va << 21;
    randomize(va,0,sets);
    for(int i = 0; i < ways; i++) {
        if(cacheData[ sets[i] ][i].valid == true){
            if ((cacheData[ sets[i] ][i].entry).logBytes != 21){
                if((cacheData[ sets[i] ][i].entry).logBytes != 12){
                    DPRINTF(TLBCache, "Size is %d\n", (cacheData[ sets[i] ][i].entry).logBytes);
                    assert(false);
                }
                continue;
            }

            if(((cacheData[ sets[i] ][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(Demap Huge) Found %x in set %d, way %d\n",va,sets[i],i);
                cacheData[ sets[i] ][i].valid = false;
                return;
            }
        }  
    }
    /* OLD
    set = (va >> 21) % sets;
    DPRINTF(TLBCache, "(DEMAP) Lookup %x in set %d\n",va, set);
    for(int i = 0; i < ways; i++) {
        if(cacheData[set][i].valid == true){
            DPRINTF(TLBCache, "(vaddr) %x ?= %x (va)\n", (cacheData[set][i].entry).vaddr, va);
            if(((cacheData[set][i].entry).vaddr) == va) {
                DPRINTF(TLBCache, "(DEMAP) Found %x in set %d, way %d\n",va,set,i);
                cacheData[set][i].valid = false;
                return;
            }
        }  
    }
    */

    }


TlbEntry* TLBCache::insert(Addr vpn, uint8_t pageOffset, TlbEntry entry){
    //DPRINTF(TLBCache, "INSERTTTTTT\n");
    // NEW
    DPRINTF(TLBCache, "(Insert) Start inserting of %x", vpn >> pageOffset);

    uint64_t addr = vpn >> pageOffset;
    addr = addr << pageOffset;

    uint64_t sets[ways] = {0};
    randomize(addr, 0, sets);

    int32_t wayIndex = -1;
    for(int i = 0; i < ways; i++) {
        if(cacheData[ sets[i] ][i].valid == false) {
            wayIndex = i;
            break;
        }
    }

    
    if (wayIndex == -1) {
        evict_cnt++;
        if(evict_cnt == MAX_EVICT) {
            rerand_requests++;
            //random_id++;
            //flushNonGlobal();
            flushAll();
            randomize(addr, 0, sets);
            for(int i = 0; i < ways; i++) {
                if(cacheData[ sets[i] ][i].valid == false) {
                    wayIndex = i;
                    break;
                }
            }
        }
    }


    if (wayIndex == -1) {
        wayIndex = evict(sets);
    };

    cacheData[ sets[wayIndex] ][wayIndex].entry = entry;
    cacheData[ sets[wayIndex] ][wayIndex].valid = true;
    cacheData[ sets[wayIndex] ][wayIndex].pageOffset = pageOffset;

    DPRINTF(TLBCache, "(Insert) Inserted %x in set %d and way %d with Page Offset %d\n",vpn, sets[wayIndex] , wayIndex, pageOffset);
    
    /* OLD
    uint64_t set = (vpn >> pageOffset) % sets;

    // Look for free entry in set
    int32_t wayIndex = -1;
    for(int i = 0; i < ways; i++) {
        if(cacheData[set][i].valid == false) {
            wayIndex = i;
            break;
        }
    }

    if (wayIndex == -1) {
        wayIndex = evict(set);
    };

    cacheData[set][wayIndex].entry = entry;
    cacheData[set][wayIndex].valid = true;
    cacheData[set][wayIndex].pageOffset = pageOffset;

    DPRINTF(TLBCache, "(Insert) Inserted %x in set %d and way %d with Page Offset %d\n",vpn, set, wayIndex, pageOffset);
    */
    
    return &(cacheData[ sets[wayIndex] ][wayIndex].entry);
}

void TLBCache::flushAll(){
    evict_cnt = 0;
    for(uint8_t i=0; i<sets; i++){
        for(uint8_t j=0; j<ways; j++){
            cacheData[i][j].valid = false;
        }
    }
    random_id++;
}

uint64_t TLBCache::getRerandRequestCount() {
    return rerand_requests;
}

uint64_t TLBCache::getGlobalPageMax() {
    return global_page_max;
}

void TLBCache::countGlobalPages() {
    uint64_t count = 0;
    for(uint8_t i=0; i<sets; i++){
        for(uint8_t j=0; j<ways; j++){
            if( cacheData[i][j].valid == true) {
                if ( (cacheData[i][j].entry).global == true) count++;
            }
        }
    }
    if(count > global_page_max) global_page_max = count;
}

}