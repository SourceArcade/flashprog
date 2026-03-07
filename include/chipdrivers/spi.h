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

#ifndef __CHIPDRIVERS_SPI_H__
#define __CHIPDRIVERS_SPI_H__ 1

#include <stdint.h>

struct flashprog_flashctx;
struct master_common;
struct bus_probe;

/* spi.c */
int spi_aai_write(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int spi_chip_write_256(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int spi_chip_read(struct flashprog_flashctx *, uint8_t *buf, unsigned int start, int unsigned len);

/* spi25.c */
struct found_id *probe_spi_rdid(const struct bus_probe *, const struct master_common *);
struct found_id *probe_spi_rems(const struct bus_probe *, const struct master_common *);
struct found_id *probe_spi_res(const struct bus_probe *, const struct master_common *);
struct found_id *probe_spi_at25f(const struct bus_probe *, const struct master_common *);

int spi_simple_write_cmd(struct flashprog_flashctx *, uint8_t op, unsigned int poll_delay);
int spi_write_enable(struct flashprog_flashctx *);
int spi_write_disable(struct flashprog_flashctx *);
int spi_block_erase_20(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_21(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_50(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_52(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_53(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_5c(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_60(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_62(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_81(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_c4(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_c7(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_d7(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_d8(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_db(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_block_erase_dc(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_chip_write_1(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int spi_nbyte_read(struct flashprog_flashctx *, uint8_t *dst, unsigned int addr, unsigned int len);
int spi_write_chunked(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len, unsigned int chunksize);
int spi_set_extended_address(struct flashprog_flashctx *, uint8_t addr_high);

enum preparation_steps;
int spi_prepare_io(struct flashprog_flashctx *, enum preparation_steps);
void spi_finish_io(struct flashprog_flashctx *);

enum flash_reg;
enum wrsr_target;
int spi_read_register(const struct flashprog_flashctx *, enum flash_reg reg, uint8_t *value);
int spi_write_register(const struct flashprog_flashctx *, enum flash_reg reg, uint8_t value, enum wrsr_target);
void spi_prettyprint_status_register_bit(uint8_t status, int bit);
int spi_prettyprint_status_register_plain(struct flashprog_flashctx *);
int spi_prettyprint_status_register_default_welwip(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp1_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp2_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp3_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp4_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp2_bpl(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp2_tb_bpl(struct flashprog_flashctx *);
int spi_disable_blockprotect(struct flashprog_flashctx *);
int spi_disable_blockprotect_bp1_srwd(struct flashprog_flashctx *);
int spi_disable_blockprotect_bp2_srwd(struct flashprog_flashctx *);
int spi_disable_blockprotect_bp3_srwd(struct flashprog_flashctx *);
int spi_disable_blockprotect_bp4_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_amic_a25l032(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25df(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25df_sec(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25f(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25f512a(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25f512b(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25f4096(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25fs010(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at25fs040(struct flashprog_flashctx *);
int spi_prettyprint_status_register_at26df081a(struct flashprog_flashctx *);
int spi_disable_blockprotect_at2x_global_unprotect(struct flashprog_flashctx *);
int spi_disable_blockprotect_at2x_global_unprotect_sec(struct flashprog_flashctx *);
int spi_disable_blockprotect_at25f(struct flashprog_flashctx *);
int spi_disable_blockprotect_at25f512a(struct flashprog_flashctx *);
int spi_disable_blockprotect_at25f512b(struct flashprog_flashctx *);
int spi_disable_blockprotect_at25fs010(struct flashprog_flashctx *);
int spi_disable_blockprotect_at25fs040(struct flashprog_flashctx *);
int spi_prettyprint_status_register_en25s_wp(struct flashprog_flashctx *);
int spi_prettyprint_status_register_n25q(struct flashprog_flashctx *);
int spi_disable_blockprotect_n25q(struct flashprog_flashctx *);
int spi_prettyprint_status_register_bp2_ep_srwd(struct flashprog_flashctx *);
int spi_disable_blockprotect_bp2_ep_srwd(struct flashprog_flashctx *);
int spi_prettyprint_status_register_sst25(struct flashprog_flashctx *);
int spi_prettyprint_status_register_sst25vf016(struct flashprog_flashctx *);
int spi_prettyprint_status_register_sst25vf040b(struct flashprog_flashctx *);
int spi_disable_blockprotect_sst26_global_unprotect(struct flashprog_flashctx *);

/* at45db.c */
int spi_prepare_at45db(struct flashprog_flashctx *, enum preparation_steps);
int spi_prettyprint_status_register_at45db(struct flashprog_flashctx *);
int spi_disable_blockprotect_at45db(struct flashprog_flashctx *);
int spi_read_at45db(struct flashprog_flashctx *, uint8_t *buf, unsigned int start, unsigned int len);
int spi_read_at45db_e8(struct flashprog_flashctx *, uint8_t *buf, unsigned int start, unsigned int len);
int spi_write_at45db(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int spi_erase_at45db_page(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_erase_at45db_block(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_erase_at45db_sector(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_erase_at45db_chip(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);
int spi_erase_at45cs_sector(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);

/* spi95.c */
struct found_id *probe_spi_st95(const struct bus_probe *, const struct master_common *);
int spi_block_erase_emulation(struct flashprog_flashctx *, unsigned int addr, unsigned int blocklen);

/* writeprotect_ranges.c */
struct wp_bits;
void decode_range_spi25(size_t *start, size_t *len, const struct wp_bits *, size_t chip_len);
void decode_range_spi25_64k_block(size_t *start, size_t *len, const struct wp_bits *, size_t chip_len);
void decode_range_spi25_bit_cmp(size_t *start, size_t *len, const struct wp_bits *, size_t chip_len);
void decode_range_spi25_2x_block(size_t *start, size_t *len, const struct wp_bits *, size_t chip_len);

/* sfdp.c */
struct found_id *probe_spi_sfdp(const struct bus_probe *, const struct master_common *);
int spi_prepare_sfdp(struct flashprog_flashctx *, enum preparation_steps);

#endif /* !__CHIPDRIVERS_SPI_H__ */
