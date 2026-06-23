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
 */

#ifndef __CHIPDRIVERS_MEMORY_BUS_H__
#define __CHIPDRIVERS_MEMORY_BUS_H__ 1

#include <stdint.h>

struct flashprog_flashctx;
struct master_common;
struct bus_probe;
struct flashchip;

/* 82802ab.c */
struct found_id *probe_82802ab(const struct bus_probe *, const struct master_common *, const struct flashchip *);
uint8_t wait_82802ab(struct flashprog_flashctx *);
int erase_block_82802ab(struct flashprog_flashctx *, unsigned int page, unsigned int pagesize);
int write_82802ab(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
void print_status_82802ab(uint8_t status);
int unlock_28f004s5(struct flashprog_flashctx *);
int unlock_lh28f008bjt(struct flashprog_flashctx *);

/* jedec.c */
struct found_id *probe_jedec(const struct bus_probe *, const struct master_common *, const struct flashchip *);
struct found_id *probe_jedec_29gl(const struct bus_probe *, const struct master_common *, const struct flashchip *);

uint8_t oddparity(uint8_t val);
void toggle_ready_jedec(const struct flashprog_flashctx *, chipaddr dst);
void data_polling_jedec(const struct flashprog_flashctx *, chipaddr dst, uint8_t data);
int write_jedec(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int write_jedec_1(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int erase_sector_jedec(struct flashprog_flashctx *, unsigned int page, unsigned int pagesize);
int erase_block_jedec(struct flashprog_flashctx *, unsigned int page, unsigned int blocksize);
int erase_chip_block_jedec(struct flashprog_flashctx *, unsigned int page, unsigned int blocksize);

int unlock_regspace2_uniform_32k(struct flashprog_flashctx *);
int unlock_regspace2_uniform_64k(struct flashprog_flashctx *);
int unlock_regspace2_block_eraser_0(struct flashprog_flashctx *);
int unlock_regspace2_block_eraser_1(struct flashprog_flashctx *);
int printlock_regspace2_uniform_64k(struct flashprog_flashctx *);
int printlock_regspace2_block_eraser_0(struct flashprog_flashctx *);
int printlock_regspace2_block_eraser_1(struct flashprog_flashctx *);

/* m28f.c */
int write_m28f(struct flashprog_flashctx *, const uint8_t *src, unsigned int pos, unsigned int len);
int erase_m28f(struct flashprog_flashctx *, unsigned int addr, unsigned int blocksize);

/* sst28sf040.c */
int erase_chip_28sf040(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int erase_sector_28sf040(struct flashprog_flashctx *, unsigned int address, unsigned int sector_size);
int write_28sf040(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int unprotect_28sf040(struct flashprog_flashctx *);
int protect_28sf040(struct flashprog_flashctx *);

/* sst49lfxxxc.c */
int erase_sector_49lfxxxc(struct flashprog_flashctx *, unsigned int address, unsigned int sector_size);

/* sst_fwhub.c */
int printlock_sst_fwhub(struct flashprog_flashctx *);
int unlock_sst_fwhub(struct flashprog_flashctx *);

/* w39.c */
int printlock_w39f010(struct flashprog_flashctx *);
int printlock_w39l010(struct flashprog_flashctx *);
int printlock_w39l020(struct flashprog_flashctx *);
int printlock_w39l040(struct flashprog_flashctx *);
int printlock_w39v040a(struct flashprog_flashctx *);
int printlock_w39v040b(struct flashprog_flashctx *);
int printlock_w39v040c(struct flashprog_flashctx *);
int printlock_w39v040fa(struct flashprog_flashctx *);
int printlock_w39v040fb(struct flashprog_flashctx *);
int printlock_w39v040fc(struct flashprog_flashctx *);
int printlock_w39v080a(struct flashprog_flashctx *);
int printlock_w39v080fa(struct flashprog_flashctx *);
int printlock_w39v080fa_dual(struct flashprog_flashctx *);
int printlock_at49f(struct flashprog_flashctx *);

/* w29ee011.c */
struct found_id *probe_w29ee011(const struct bus_probe *, const struct master_common *, const struct flashchip *);

/* stm50.c */
int erase_sector_stm50(struct flashprog_flashctx *, unsigned int block, unsigned int blocksize);

/* en29lv640b.c */
int probe_en29lv640b(struct flashprog_flashctx *);
int write_en29lv640b(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);

/* memory_bus.c */
struct memory_chip_info {
	chipsize_t chip_size;
	feature_bits_t chip_features;
	signed int probe_timing;
};

struct memory_found_id {
	struct found_id generic;
	struct memory_chip_info memory_info;
};

struct memory_found_id *alloc_memory_found_id(void);

struct par_master;
void *programmer_map_flash_data(const struct par_master *, chipsize_t, const char *descr);
void programmer_unmap_flash_region(const struct par_master *, void *, chipsize_t);

enum preparation_steps;
int prepare_memory_access(struct flashprog_flashctx *, enum preparation_steps);
int prepare_memory_register_access(struct flashprog_flashctx *, enum preparation_steps);
void finish_memory_access(struct flashprog_flashctx *);

#endif /* !__CHIPDRIVERS_MEMORY_BUS_H__ */
