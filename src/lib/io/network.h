#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file io/network.h
 * @brief Receive packets
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(network_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_network_s fr_network_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/util/log.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t	max_outstanding;
} fr_network_config_t;

int		fr_network_listen_add(fr_network_t *nr, fr_listen_t *li) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int		fr_network_listen_delete(fr_network_t *nr, fr_listen_t *li) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int		fr_network_directory_add(fr_network_t *nr, fr_listen_t *li) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int		fr_network_worker_add(fr_network_t *nr, fr_worker_t *worker) CC_HINT(nonnull) CC_HINT(warn_unused_result);

void		fr_network_worker_add_self(fr_network_t *nr, fr_worker_t *worker) CC_HINT(nonnull);

void		fr_network_listen_read(fr_network_t *nr, fr_listen_t *li) CC_HINT(nonnull);

void		fr_network_listen_write(fr_network_t *nr, fr_listen_t *li, uint8_t const *packet, size_t packet_len,
					void *packet_ctx, fr_time_t request_time) CC_HINT(nonnull);

int		fr_network_listen_inject(fr_network_t *nr, fr_listen_t *li, uint8_t const *packet, size_t packet_len, fr_time_t recv_time) CC_HINT(warn_unused_result);

int		fr_network_sendto_worker(fr_network_t *nr, fr_listen_t *li, void *packet_ctx, uint8_t const *data, size_t data_len, fr_time_t recv_time) CC_HINT(warn_unused_result);

int		fr_network_listen_send_packet(fr_network_t *nr, fr_listen_t *parent, fr_listen_t *li,
					      const uint8_t *buffer, size_t buflen, fr_time_t recv_time, void *packet_ctx) CC_HINT(nonnull(1,2,3,4)) CC_HINT(warn_unused_result);

size_t		fr_network_listen_outstanding(fr_network_t *nr, fr_listen_t *li) CC_HINT(warn_unused_result);

fr_network_t	*fr_network_create(TALLOC_CTX *ctx, fr_event_list_t *el,
				   char const *nr, fr_log_t const *logger, fr_log_lvl_t lvl,
				   fr_network_config_t const *config) CC_HINT(nonnull(2,4)) CC_HINT(warn_unused_result);

int		fr_network_exit(fr_network_t *nr) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int		fr_network_destroy(fr_network_t *nr) CC_HINT(nonnull) CC_HINT(warn_unused_result);

void		fr_network(fr_network_t *nr) CC_HINT(nonnull);

int		fr_network_stats(fr_network_t const *nr, int num, uint64_t *stats) CC_HINT(nonnull) CC_HINT(warn_unused_result);

void		fr_network_stats_log(fr_network_t const *nr, fr_log_t const *log) CC_HINT(nonnull);

extern fr_cmd_table_t cmd_network_table[];

#ifdef __cplusplus
}
#endif
