/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Carl-Daniel Hailfinger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Header file for flash chip drivers. Included from flash.h.
 * As a general rule, every function listed here should take a pointer to
 * struct flashctx as first parameter.
 */

#ifndef __CHIPDRIVERS_H__
#define __CHIPDRIVERS_H__ 1

#include "flash.h"	/* for chipaddr and flashctx */

/* opaque.c */
int probe_opaque(struct flashctx *flash);
int read_opaque(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len);
int write_opaque(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
int erase_opaque(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen);

/* 82802ab.c */
uint8_t wait_82802ab(struct flashctx *flash);
int probe_82802ab(struct flashctx *flash);
int erase_block_82802ab(struct flashctx *flash, unsigned int page, unsigned int pagesize);
int write_82802ab(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
void print_status_82802ab(uint8_t status);
int unlock_28f004s5(struct flashctx *flash);
int unlock_lh28f008bjt(struct flashctx *flash);

/* jedec.c */
uint8_t oddparity(uint8_t val);
void toggle_ready_jedec(const struct flashctx *flash, chipaddr dst);
void data_polling_jedec(const struct flashctx *flash, chipaddr dst, uint8_t data);
int probe_jedec(struct flashctx *flash);
int probe_jedec_29gl(struct flashctx *flash);
int write_jedec(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
int write_jedec_1(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
int erase_sector_jedec(struct flashctx *flash, unsigned int page, unsigned int pagesize);
int erase_block_jedec(struct flashctx *flash, unsigned int page, unsigned int blocksize);
int erase_chip_block_jedec(struct flashctx *flash, unsigned int page, unsigned int blocksize);

int unlock_regspace2_uniform_32k(struct flashctx *flash);
int unlock_regspace2_uniform_64k(struct flashctx *flash);
int unlock_regspace2_block_eraser_0(struct flashctx *flash);
int unlock_regspace2_block_eraser_1(struct flashctx *flash);
int printlock_regspace2_uniform_64k(struct flashctx *flash);
int printlock_regspace2_block_eraser_0(struct flashctx *flash);
int printlock_regspace2_block_eraser_1(struct flashctx *flash);

/* sst28sf040.c */
int erase_chip_28sf040(struct flashctx *flash, unsigned int addr, unsigned int blocklen);
int erase_sector_28sf040(struct flashctx *flash, unsigned int address, unsigned int sector_size);
int write_28sf040(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
int unprotect_28sf040(struct flashctx *flash);
int protect_28sf040(struct flashctx *flash);

/* sst49lfxxxc.c */
int erase_sector_49lfxxxc(struct flashctx *flash, unsigned int address, unsigned int sector_size);

/* sst_fwhub.c */
int printlock_sst_fwhub(struct flashctx *flash);
int unlock_sst_fwhub(struct flashctx *flash);

/* w39.c */
int printlock_w39f010(struct flashctx * flash);
int printlock_w39l010(struct flashctx * flash);
int printlock_w39l020(struct flashctx * flash);
int printlock_w39l040(struct flashctx * flash);
int printlock_w39v040a(struct flashctx *flash);
int printlock_w39v040b(struct flashctx *flash);
int printlock_w39v040c(struct flashctx *flash);
int printlock_w39v040fa(struct flashctx *flash);
int printlock_w39v040fb(struct flashctx *flash);
int printlock_w39v040fc(struct flashctx *flash);
int printlock_w39v080a(struct flashctx *flash);
int printlock_w39v080fa(struct flashctx *flash);
int printlock_w39v080fa_dual(struct flashctx *flash);
int printlock_at49f(struct flashctx *flash);

/* w29ee011.c */
int probe_w29ee011(struct flashctx *flash);

/* stm50.c */
int erase_sector_stm50(struct flashctx *flash, unsigned int block, unsigned int blocksize);

/* en29lv640b.c */
int probe_en29lv640b(struct flashctx *flash);
int write_en29lv640b(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);

/* memory_bus.c */
int prepare_memory_access(struct flashctx *, enum preparation_steps);
int prepare_memory_register_access(struct flashctx *, enum preparation_steps);
void finish_memory_access(struct flashctx *);

#endif /* !__CHIPDRIVERS_H__ */
