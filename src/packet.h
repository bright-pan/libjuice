#ifndef _PACKET_FIFO_H_
#define _PACKET_FIFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ring_fifo.h"

typedef ring_fifo_t packet_fifo_t;

// int packet_fifo_read(packet_fifo_t *fifo, packet_frame_t *frame);
// int packet_fifo_write(packet_fifo_t *fifo, packet_frame_t *frame);
int packet_fifo_read(packet_fifo_t *fifo, void *data, size_t size);
int packet_fifo_write(packet_fifo_t *fifo, void *data, size_t size);
void packet_fifo_reset(packet_fifo_t *fifo);
void packet_fifo_clear(packet_fifo_t *fifo, uint32_t size);
uint32_t packet_fifo_size(packet_fifo_t *fifo);
uint32_t packet_fifo_len(packet_fifo_t *fifo);
uint32_t packet_fifo_avail(packet_fifo_t *fifo);
void packet_fifo_init(packet_fifo_t *fifo);

#ifdef __cplusplus
}
#endif

#endif /* _PACKET_FIFO_H_ */
