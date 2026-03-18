/* Modifications Copyright (C) 2023 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2, as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * BitCracker: BitLocker password cracking tool, CUDA version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *			    Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 * 
 * This file is part of the BitCracker project: https://github.com/e-ago/bitcracker
 * 
 * BitCracker is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * BitCracker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with BitCracker. If not, see <http://www.gnu.org/licenses/>.
 */

#include <sycl/sycl.hpp>
#include "bitcracker.h"
#include "aes.h"

#define TIMER_START_() time_start_ = std::chrono::steady_clock::now();
#define TIMER_END_()                                                                         \
    time_end_ = std::chrono::steady_clock::now();                                            \
    time_total_  += std::chrono::duration<double, std::milli>(time_end_ - time_start_).count();
#define TIMER_PRINT_(name) std::cout << name <<": " << time_total_ / 1e3 << " s\n";

#ifndef DEBUG_TIME
#define DEBUG_TIME
#endif

void encrypt(
	uint32_t k0,
	uint32_t k1,
	uint32_t k2,
	uint32_t k3,
	uint32_t k4,
	uint32_t k5,
	uint32_t k6,
	uint32_t k7,
	uint32_t m0,
	uint32_t m1,
	uint32_t m2,
	uint32_t m3,
	uint32_t * output0,
	uint32_t * output1,
	uint32_t * output2,
	uint32_t * output3,
	unsigned int *TS0,
	unsigned int *TS1,
	unsigned int *TS2,
	unsigned int *TS3)
{
	uint32_t enc_schedule0, enc_schedule1, enc_schedule2, enc_schedule3, enc_schedule4, enc_schedule5, enc_schedule6, enc_schedule7;
	uint32_t local_key0, local_key1, local_key2, local_key3, local_key4, local_key5, local_key6, local_key7;

	local_key0 = k0;
	local_key1 = k1;
	local_key2 = k2;
	local_key3 = k3;
	local_key4 = k4;
	local_key5 = k5;
	local_key6 = k6;
	local_key7 = k7;

    /*
    DPCT1004:55: Compatible DPC++ code could not be generated.
    enc_schedule0 = __byte_perm(m0, 0, 0x0123) ^ local_key0;
    */
    enc_schedule0 = __builtin_bswap32(m0) ^ local_key0;

    /*
    DPCT1004:56: Compatible DPC++ code could not be generated.
    enc_schedule1 = __byte_perm(m1, 0, 0x0123) ^ local_key1;
    */
    enc_schedule1 = __builtin_bswap32(m1) ^ local_key1;

    /*
    DPCT1004:57: Compatible DPC++ code could not be generated.
    enc_schedule2 = __byte_perm(m2, 0, 0x0123) ^ local_key2;
    */
    enc_schedule2 = __builtin_bswap32(m2) ^ local_key2;
    
    /*
    DPCT1004:58: Compatible DPC++ code could not be generated.
    enc_schedule3 = __byte_perm(m3, 0, 0x0123) ^ local_key3;
    */
    enc_schedule3 = __builtin_bswap32(m3) ^ local_key3;

    enc_schedule4 = enc_schedule3;
	enc_schedule5 = enc_schedule3;
	enc_schedule6 = enc_schedule3;
	enc_schedule7 = enc_schedule3;


	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x02000000; //RCON[1];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x04000000; //RCON[2];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x08000000; //RCON[3];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x10000000; //RCON[4];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x20000000; //RCON[5];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;


    /*
    DPCT1004:59: Compatible DPC++ code could not be generated.
    output0[0] = __byte_perm(enc_schedule0, 0, 0x0123);
    */
    output0[0] = __builtin_bswap32(enc_schedule0);

    /*
    DPCT1004:60: Compatible DPC++ code could not be generated.
    output1[0] = __byte_perm(enc_schedule1, 0, 0x0123);
    */
    output1[0] = __builtin_bswap32(enc_schedule1);

    /*
    DPCT1004:61: Compatible DPC++ code could not be generated.
    output2[0] = __byte_perm(enc_schedule2, 0, 0x0123);
    */
    output2[0] = __builtin_bswap32(enc_schedule2);

    /*
    DPCT1004:62: Compatible DPC++ code could not be generated.
    output3[0] = __byte_perm(enc_schedule3, 0, 0x0123);
    */
    output3[0] = __builtin_bswap32(enc_schedule3);
}

void decrypt_vmk_with_mac(
    uint32_t num_pswd_per_kernel_launch,
    int *found,
    unsigned char * vmkKey,
    unsigned char * vmkIV,
    unsigned char * mac,
    unsigned char * macIV,
    unsigned char * computedMacIV,
    int v0,
    int v1,
    int v2,
    int v3,
    uint32_t s0,
    uint32_t s1,
    uint32_t s2,
    uint32_t s3,
    uint32_t *pswd_uint32,
    uint32_t *w_words_uint32,
    unsigned int *TS0,
    unsigned int *TS1,
    unsigned int *TS2,
    unsigned int *TS3 ,
    sycl::nd_item<1> item //, sycl::stream out
    )
{
   	uint32_t schedule00, schedule01;
	uint32_t hash0;
	uint32_t a, b, c, d, e, f, g, h;
	a = b = c = d = e = f = g = h = 0;
	hash0 = 0;

   	schedule00 = schedule01 = 0;

    unsigned int tid = item.get_global_id(0);
    if (tid >= num_pswd_per_kernel_launch) return;
    int index_generic;  // goes from 0-0x100000

	// while(tid < num_pswd_per_kernel_launch)
	{
		a = UINT32_C(0x6A09E667);

    /**********************************************************************
    ***************************** FIRST HASH ******************************
    **********************************************************************/

        schedule00 = (uint32_t)(pswd_uint32[0]);

        ALL_SCHEDULE_LAST16()
        ALL_ROUND_B1_1()
        ALL_ROUND_B1_2()


    /**********************************************************************
    ***************************** LOOP HASH *******************************
    **********************************************************************/

		hash0 = 0;

		for(index_generic = 0; index_generic < NUM_HASH_BLOCKS; index_generic++)
		{

            // execute first 32 rounds
			ALL_ROUND_B1_1()

            // compute second 32 W words
			ALL_SCHEDULE32()

            // executer second 32 rounds
			ALL_ROUND_B1_2()

            // update hash value
			hash0 += a;

		}

    /**********************************************************************
    *************************** MAC COMPARISON ****************************
    **********************************************************************/

        encrypt(
            hash0, 0, 0, 0, 0, 0, 0, 0,
            a, 0, 0, 0,
            &(schedule00), &(schedule01), &(schedule00), &(schedule00),
            TS0, TS1, TS2, TS3
        );

        encrypt(
            hash0, 0, 0, 0, 0, 0, 0, 0,
            a, 0, 0, 0,
            &(schedule00), &(schedule01), &(schedule00), &(schedule00),
            TS0, TS1, TS2, TS3
        );
        if (schedule00 == 7)
            *found = 1;
    }

	return;
}

int 	*h_found;
char	*h_pswd_char;       // used only for printing purpose, never moved to device
int     pswd_per_thread = 1;               // only for printing
char	printed_pswd[PSWD_NUM_CHAR + 1];   // only for printing

static int check_match() {
    int	out_pswd_ind;
	if (*h_found >= 0){
		out_pswd_ind = *h_found;
		snprintf((char*)printed_pswd, PSWD_NUM_CHAR, "%s", (char *)(h_pswd_char + out_pswd_ind * PSWD_NUM_CHAR));
		for (int i = 0; i < PSWD_NUM_CHAR; i++) {
			if (printed_pswd[i] == (char)0x80 || printed_pswd[i] == (char)0xffffff80) {
                printed_pswd[i] = '\0';
            }
        }
		return 1;
	}
	return 0;
}

double attack(
    char *dname,
    uint32_t* d_w_words_uint32,
    unsigned char* encryptedVMK,
    unsigned char* nonce,
    unsigned char* encryptedMAC,
    int gridBlocks,
    double& duration,
    sycl::queue qbc)
{
    try {
    std::chrono::steady_clock::time_point time_start_;
    std::chrono::steady_clock::time_point time_end_;
    double time_total_ = 0.0;

    FILE			*fp;
	// int				done = 0;
	int				match = 0;
	int				h_w_words_uint32[4];
	uint32_t		num_read_pswd;
	// int				cudaThreads = CUDA_THREADS_NO_MAC;
	long long		tot_num_read_pswd = 0;
	uint8_t			vmkIV[IV_SIZE], *d_vmkIV, *d_vmk;
	uint8_t			macIV[IV_SIZE], *d_macIV, *d_mac;
	uint8_t			computedMacIV[IV_SIZE];
	uint8_t			*d_computedMacIV;

    int*			d_found;
    uint32_t*		h_pswd_uint32;     // uint32 representation of passwords in host
    uint32_t* 		d_pswd_uint32;     // uint32 representation of passwords in device

    unsigned int*   d_TS0;
    unsigned int*   d_TS1;
    unsigned int*   d_TS2;
    unsigned int*   d_TS3;

	if(dname == NULL || d_w_words_uint32 == NULL || encryptedVMK == NULL)
	{
		fprintf(stderr, "Attack input error\n");
		return 0.0;
	}

	if(max_num_pswd_per_read <= 0)
	{
		fprintf(stderr, "Attack tot passwords error: %d\n", max_num_pswd_per_read);
		return 0.0;
	}
	
	//-------- vmkIV setup ------
	memset(vmkIV, 0, IV_SIZE);
	vmkIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
	memcpy(vmkIV + 1, nonce, NONCE_SIZE);
	if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
	{
		fprintf(stderr, "Attack nonce error\n");
		return 0.0;
	}
	vmkIV[IV_SIZE - 1] = 1; 
	// -----------------------

    // cudaThreads = THREADS_PER_BLOCK;

    //-------- macIV setup ------
    memset(macIV, 0, IV_SIZE);
    macIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
    memcpy(macIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Attack nonce error\n");
        return 0.0;
    }
    macIV[IV_SIZE - 1] = 0; 
    // -----------------------

    //-------- computedMacIV setup ------
    memset(computedMacIV, 0, IV_SIZE);
    computedMacIV[0] = 0x3a;
    memcpy(computedMacIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Attack nonce error\n");
        return 0.0;
    }
    computedMacIV[IV_SIZE - 1] = 0x2c;

	// ---- Open File Dictionary ----
	if (!memcmp(dname, "-\0", 2)) {
		fp = stdin;
	} else {
		fp = fopen(dname, "r");
		if (!fp) {
			fprintf(stderr, "Can't open dictionary file %s.\n", dname);
			return 0.0;
		}
	}
	// -------------------------------

    // ---- HOST VARS ----
    h_found        = sycl::malloc_host<int>(     1,                                        qbc);
    h_pswd_char    = sycl::malloc_host<char>(    max_num_pswd_per_read * PSWD_NUM_CHAR,    qbc);
    h_pswd_uint32  = sycl::malloc_host<uint32_t>(max_num_pswd_per_read * PSWD_NUM_UINT32,  qbc);
    *h_found = -1;
    // h_pswd_char is later populated in read_password(). It is never copied over to device.
    // h_pswd_uint32 is populated in read_password() and copied over to device.
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

#ifdef DEBUG_TIME
    auto time11 = std::chrono::steady_clock::now();
#endif

    qbc.memcpy(h_w_words_uint32, d_w_words_uint32, 4 * sizeof(int));
    // ------------------------

    // ---- DEVICE VARS are d_vmk, d_vmkIV, d_mac, d_macIV, d_computedMacIV, d_found, d_w_words_uint32, d_pswd_uint32 ----
    d_vmk           = sycl::malloc_device<uint8_t>( VMK_FULL_SIZE, qbc);
    d_vmkIV         = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_mac           = sycl::malloc_device<uint8_t>( MAC_SIZE,      qbc);
    d_macIV         = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_computedMacIV = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_found         = sycl::malloc_device<int>(     1,             qbc);

    d_pswd_uint32   = sycl::malloc_device<uint32_t>(max_num_pswd_per_read * PSWD_NUM_UINT32,   qbc);
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

    d_TS0 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS1 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS2 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS3 = sycl::malloc_device<unsigned int>(256, qbc);

    qbc.memcpy(d_vmk,             encryptedVMK,   VMK_FULL_SIZE   * sizeof(uint8_t));
    qbc.memcpy(d_vmkIV,           vmkIV,          IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_mac,             encryptedMAC,   MAC_SIZE        * sizeof(uint8_t));
    qbc.memcpy(d_macIV,           macIV,          IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_computedMacIV,   computedMacIV,  IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_found,           h_found,                          sizeof(uint32_t));
    // d_pswd_uint32 is allocated above but copied from h_pswd_uint32 in while loop below
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

    qbc.memcpy(d_TS0, h_TS0, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS1, h_TS1, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS2, h_TS2, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS3, h_TS3, 256 * sizeof(unsigned int));

    qbc.wait();

#ifdef DEBUG_TIME
    auto time12 = std::chrono::steady_clock::now();
    auto duration1 = std::chrono::duration<double, std::micro>(time12 - time11).count();
    duration += duration1;
    std::cout << "attack() - alloc + memcpy, duration1: " << duration1 << " us\n\n";
#endif

    printf("Type of attack: %s\n", "User Password");
	// printf("CUDA threads per block: %d\n", cudaThreads);
	// printf("CUDA Blocks: %d\n", gridBlocks);
	printf("Psw per thread: %d\n", pswd_per_thread);
	printf("max_num_pswd_per_read: %d\n", max_num_pswd_per_read);
	printf("Dictionary: %s\n", (fp == stdin) ? "standard input" : dname);
	printf("MAC Comparison (-m): %s\n", "Yes");
	printf("\n");

    auto v0 = h_w_words_uint32[0];
    auto v1 = h_w_words_uint32[1];
    auto v2 = h_w_words_uint32[2];
    auto v3 = h_w_words_uint32[3];

	uint32_t s0 =  ((uint32_t)salt[ 0]) << 24 | ((uint32_t)salt[ 1]) << 16 | ((uint32_t)salt[ 2]) <<  8 | ((uint32_t)salt[ 3]); 
	uint32_t s1 =  ((uint32_t)salt[ 4]) << 24 | ((uint32_t)salt[ 5]) << 16 | ((uint32_t)salt[ 6]) <<  8 | ((uint32_t)salt[ 7]); 
	uint32_t s2 =  ((uint32_t)salt[ 8]) << 24 | ((uint32_t)salt[ 9]) << 16 | ((uint32_t)salt[10]) <<  8 | ((uint32_t)salt[11]);
	uint32_t s3 =  ((uint32_t)salt[12]) << 24 | ((uint32_t)salt[13]) << 16 | ((uint32_t)salt[14]) <<  8 | ((uint32_t)salt[15]);

    int iter = 0;
	while(true) {
        iter++;

        TIMER_START_()
        // populate h_pswd_uint32 and h_pswd_char
        num_read_pswd = read_password(&h_pswd_uint32, &h_pswd_char, max_num_pswd_per_read, fp);
        if(num_read_pswd <= 0) {
            break;
        }
        std::cout <<"\nIter: " << iter<< ", num passwords read: " << num_read_pswd << std::endl;
        TIMER_END_()

#ifdef DEBUG_TIME
        auto time_iter11 = std::chrono::steady_clock::now();
        auto time21 = std::chrono::steady_clock::now();
#endif

        // copy h_pswd_uint32 over to d_pswd_uint32
        auto e1 = qbc.memcpy(d_pswd_uint32, h_pswd_uint32, num_read_pswd * PSWD_NUM_UINT32 * sizeof(uint32_t));
        qbc.wait();

        auto time22 = std::chrono::steady_clock::now();
        auto duration2 = std::chrono::duration<double, std::micro>(time22 - time21).count();
        duration += duration2;
        std::cout << "attack() - memcpy H2D: " << duration2 << " us\n\n";

        auto time31 = std::chrono::steady_clock::now();

        // launch kernel
        unsigned int wg_size  = 256; // wg_size tuned to 256
        unsigned int in_range = ((num_read_pswd + wg_size -1) / wg_size) * wg_size;
        auto e2 = qbc.submit([&](sycl::handler &cgh) {
            cgh.depends_on(e1);
            cgh.parallel_for(
                sycl::nd_range<1>(in_range, wg_size),
                [=](sycl::nd_item<1> item)
            #if !defined(USE_NVIDIA_BACKEND) && !defined(USE_AMDHIP_BACKEND)
                [[sycl::reqd_sub_group_size(16)]]
            #endif
                {
                    decrypt_vmk_with_mac(
                        num_read_pswd,
                        d_found,
                        d_vmk,
                        d_vmkIV,
                        d_mac,
                        d_macIV,
                        d_computedMacIV,
                        v0,
                        v1,
                        v2,
                        v3,
                        s0,
                        s1,
                        s2,
                        s3,
                        d_pswd_uint32,
                        d_w_words_uint32,
                        d_TS0,
                        d_TS1,
                        d_TS2,
                        d_TS3,
                        item
                    );
                }
            );
        });
        qbc.wait();

        auto time32 = std::chrono::steady_clock::now();
        auto duration3 = std::chrono::duration<double, std::micro>(time32 - time31).count();
        duration += duration3;
        std::cout << "attack() - decrypt_vmk_with_mac(): " << duration3 << " us\n\n";

        auto time41 = std::chrono::steady_clock::now();

        // copy d_found from device to h_found in host
        qbc.memcpy(h_found, d_found, sizeof(unsigned int), std::move(e2));
        qbc.wait();

        auto time42 = std::chrono::steady_clock::now();
        auto duration4 = std::chrono::duration<double, std::micro>(time42 - time41).count();
        duration += duration4;
        std::cout << "attack() - memcpy D2H: " << duration4 << " us\n\n";

#ifdef DEBUG_TIME
        auto time_iter12 = std::chrono::steady_clock::now();
        auto duration_iter = std::chrono::duration<double, std::micro>(time_iter12 - time_iter11).count();
        duration += duration_iter;
        std::cout << "H2D + decrypt_vmk_with_mac() + D2H: " << duration_iter << " us\n\n";
#endif

        printf("Kernel execution:\n"
                "\tEffective passwords: %d\n"
                "\tPasswords Range:\n"
                "\t\t%s\n"
                "\t\t.....\n"
                "\t\t%s\n",
                num_read_pswd,
                (char *)(h_pswd_char),                                          // first password in batch
                (char *)(h_pswd_char + ((num_read_pswd - 1) * PSWD_NUM_CHAR)));  // last password in batch
        std::cout << "--------------------\n";

        tot_num_read_pswd += num_read_pswd;
        match = check_match();  // uses h_found
        if(match || feof(fp)) {
            break;
        }
	}

    std::cout << "================================================\n"
              << "Bitcracker attack completed\n"
              << "Total passwords evaluated: " << tot_num_read_pswd << std::endl;
    if (match == 1) std::cout << "Password found: " << printed_pswd << std::endl;
    else std::cout << "Password not found!\n";
    std::cout << "================================================\n";

    // close file
	if (fp != stdin)
		fclose(fp);

    // free host allocated variables
    sycl::free(h_found,         qbc);
    sycl::free(h_pswd_char,     qbc);
    sycl::free(h_pswd_uint32,   qbc);
    // free device allocated variables
    sycl::free(d_vmk,           qbc);
    sycl::free(d_vmkIV,         qbc);
    sycl::free(d_mac,           qbc);
    sycl::free(d_macIV,         qbc);
    sycl::free(d_computedMacIV, qbc);
    sycl::free(d_found,         qbc);
    sycl::free(d_pswd_uint32,   qbc);
    sycl::free(d_TS0,           qbc);
    sycl::free(d_TS1,           qbc);
    sycl::free(d_TS2,           qbc);
    sycl::free(d_TS3,           qbc);

    TIMER_PRINT_("time to subtract from total")
	return time_total_;
    }
    catch (sycl::exception const &exc) {
        std::cerr << exc.what() << "Exception caught at file:" << __FILE__ << ", line:" << __LINE__ << std::endl;
        std::exit(1);
    }
}
