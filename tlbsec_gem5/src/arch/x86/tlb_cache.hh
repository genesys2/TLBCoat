#ifndef __ARCH_X86_TLBCache_HH__
#define __ARCH_X86_TLBCache_HH__

#include "debug/TLBCache.hh"

#include "arch/x86/pagetable.hh"
#include "sim/sim_object.hh"
#include "params/TLBCache.hh"
#include "sim/stats.hh"

namespace X86ISA{

    class TLBCache : public SimObject
        {
            private:
                uint8_t ways, sets;

                struct TLBMeta { 
                    bool valid; 
                    TlbEntry entry;
                    uint8_t pageOffset; 
                };

                TLBMeta **cacheData;

                uint64_t prince_key;
                uint64_t random_id;
                uint32_t evict_cnt;

                uint64_t rerand_requests;
                uint64_t global_page_max;

                static uint8_t prince_sbox(uint8_t index){
                    const uint8_t sbox[] = {0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4};  
                    return sbox[index & 0xF];
                }

                static uint8_t prince_sbox_inv(uint8_t index){
                    const uint8_t sbox_inv[] = {0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1};
                    return sbox_inv[index & 0xF];
                }

                static uint64_t gf2_mul_16(const uint64_t in, const uint32_t mat[16]){
                    uint64_t out = 0;
                    uint8_t i;
                    for(i = 0; i < 16; i++){
                    if((in >> i) & 1){
                        out ^= mat[i];
                    }
                    }
                    return out;
                }

                static void prince_m_prime_layer(uint64_t *prince_block){
                    static const uint32_t m_0[16] = {
                    0x0111, 0x2220, 0x4404, 0x8088,
                    0x1011, 0x0222, 0x4440, 0x8808,
                    0x1101, 0x2022, 0x0444, 0x8880,
                    0x1110, 0x2202, 0x4044, 0x0888
                    };
                    
                    static const uint32_t m_1[16] = {
                    0x1110, 0x2202, 0x4044, 0x0888, 
                    0x0111, 0x2220, 0x4404, 0x8088,
                    0x1011, 0x0222, 0x4440, 0x8808,
                    0x1101, 0x2022, 0x0444, 0x8880
                    };

                    const uint64_t out_0 = gf2_mul_16(*prince_block, m_0);
                    const uint64_t out_1 = gf2_mul_16(*prince_block >> 16, m_1);
                    const uint64_t out_2 = gf2_mul_16(*prince_block >> 32, m_1);
                    const uint64_t out_3 = gf2_mul_16(*prince_block >> 48, m_0);
                    *prince_block = (out_3 << 48) | (out_2 << 32) | (out_1 << 16) | out_0;
                    
                    //return m_prime_out;
                }

                const static uint64_t prince_row_mask = UINT64_C(0xF000F000F000F000);

                static void prince_shift_rows(uint64_t* prince_block, int inverse){
                    uint64_t out = 0;
                    for(uint8_t i = 0; i < 4; ++i){
                    const uint64_t row = *prince_block & (prince_row_mask >> (4*i));
                    const unsigned int shift = inverse ? i*16 : 64-i*16;
                    out |= (row >> shift) | (row << (64-shift));
                    }
                    *prince_block = out;
                }

                static void prince_s_layer(uint64_t* prince_block){
                    uint64_t out = 0;
                    for(uint8_t i=15; i > 0; --i){
                        out |= prince_sbox((*prince_block) >> (i << 2));
                        out <<= 4;
                    }
                    out |= prince_sbox(*prince_block);
                    *prince_block = out;
                }

                static void prince_s_layer_inv(uint64_t* prince_block){
                    uint64_t out = 0;
                    for(uint8_t i=15; i > 0; --i){
                        out |= prince_sbox_inv(*prince_block >> (i << 2));
                        out <<= 4;
                    }
                    out |= prince_sbox_inv(*prince_block);
                    *prince_block = out;
                }


                static void prince_m_layer(uint64_t *prince_block){
                    prince_m_prime_layer(prince_block);
                    prince_shift_rows(prince_block, 0);
                }

                static void prince_m_layer_inv(uint64_t *prince_block){
                    prince_shift_rows(prince_block, 1);
                    prince_m_prime_layer(prince_block);
                }

                static uint64_t encrypt(uint64_t input, uint64_t key) {
                    uint64_t output = input;
                    output ^= key;
                    output ^= 0x13198a2e03707344; // RC1
                    prince_m_layer(&output);
                    prince_s_layer_inv(&output);

                    // PRINCE' round 2
                    output ^= key;
                    output ^= 0xa4093822299f31d0; // RC2
                    prince_m_layer(&output);
                    prince_s_layer(&output);

                    output ^= key;

                    prince_s_layer(&output);
                    prince_m_prime_layer(&output);

                    return output;
                }
                void randomize(Addr va, uint64_t process_id, uint64_t* set_arr);
            protected:
                // uint8_t get_set(Addr vpn, uint8_t way);

            public:
                TLBCache(const TLBCacheParams &p);
                ~TLBCache();
                TlbEntry* lookup(Addr va);
                void demapPage(Addr va, uint64_t asn);
                void flushNonGlobal();
                uint8_t evict(uint64_t* set_arr);
                TlbEntry* insert(Addr vpn, uint8_t pageOffset, TlbEntry entry);
                void flushAll();
                uint64_t getRerandRequestCount();
                uint64_t getGlobalPageMax();
                void countGlobalPages();
        };
}
#endif