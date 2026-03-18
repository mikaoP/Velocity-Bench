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
 *							Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
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

#define ROR07(x) (((x) << 25) | ((x) >> 7))
#define ROR18(x) (((x) << 14) | ((x) >> 18))

#define ROR17(x) (((x) << 15) | ((x) >> 17))
#define ROR19(x) (((x) << 13) | ((x) >> 19))

// #define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define __dpcpp_inline__ __inline__ __attribute__((always_inline))

static __dpcpp_inline__ uint32_t LOP3LUT_XOR(uint32_t a, uint32_t b, uint32_t c) {
    return a^b^c;
}

static __dpcpp_inline__ uint32_t LOP3LUT_XORAND(uint32_t g, uint32_t e, uint32_t f) {
    return (g ^ (e & (f ^ g)));
}

static __dpcpp_inline__ uint32_t LOP3LUT_ANDOR(uint32_t a, uint32_t b, uint32_t c) {
    return  ((a & (b | c)) | (b & c));
}

#define SCHEDULE00()  \
		schedule00 = schedule00 + schedule00 \
			+ LOP3LUT_XOR(ROR07(schedule00) , ROR18(schedule00) , (schedule00 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule00) , ROR19(schedule00) , (schedule00 >> 10));

#define ROR06(x) (((x) << 26) | ((x) >> 6))
#define ROR11(x) (((x) << 21) | ((x) >> 11))
#define ROR25(x) (((x) << 7) | ((x) >> 25))

#define ROR02(x) (((x) << 30) | ((x) >> 2))
#define ROR13(x) (((x) << 19) | ((x) >> 13))
#define ROR22(x) (((x) << 10) | ((x) >> 22))

#define ROUND(a, b, c, d, e, f, g, h, W, k) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k + W; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, i, k, indexW) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k + w_words_uint32[(indexW + i)]; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h, i, k, w) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k +  w; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ALL_SCHEDULE_LAST16() \
		SCHEDULE00() 

#define ALL_SCHEDULE32() \
		SCHEDULE00() 

#define ALL_ROUND_B1_1() \
		ROUND(a, b, c, d, e, f, g, h, schedule00, 0x428A2F98) \
		ROUND(b, c, d, e, f, g, h, a, schedule00, 0xAB1C5ED5)

#define ALL_ROUND_B1_2() \
        ROUND(a, b, c, d, e, f, g, h, schedule00, 0x27B70A85) \
        ROUND(b, c, d, e, f, g, h, a, schedule00, 0x92722C85)
