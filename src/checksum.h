/* Copyright (c) 2025 Sergio Randriamihoatra.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PONG_CHECKSUM_H
#define PONG_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

/* RFC 1071 Internet checksum over @len bytes of @data. */
uint16_t checksum(const void *data, size_t len);

#endif /* PONG_CHECKSUM_H */
