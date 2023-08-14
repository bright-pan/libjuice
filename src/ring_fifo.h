#ifndef _RING_FIFO_H_
#define _RING_FIFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <aos/kernel.h>
#include <aos/cli.h>
#include "config.h"

// os port
typedef aos_mutex_t ring_fifo_mutex_t;
typedef aos_sem_t ring_fifo_sem_t;

#define RING_FIFO_LOCK(fifo) aos_mutex_lock(&fifo->mutex, AOS_WAIT_FOREVER)
#define RING_FIFO_UNLOCK(fifo) aos_mutex_unlock(&fifo->mutex)
#define RING_FIFO_MUTEX_INIT(fifo) aos_mutex_new(&fifo->mutex)
#define RING_FIFO_CALLOC(nums, size) juice_calloc(nums, size);
#define RING_FIFO_MALLOC(size) juice_malloc(size)
#define RING_FIFO_FREE(ptr) juice_free(ptr)
#define RING_FIFO_SEM_INIT(fifo) aos_sem_new(&fifo->sem, 0)

// common
typedef struct {
    void *buffer;
    uint32_t size; // 缓冲区支持的最大块数量
    uint32_t write; //块写序号
    uint32_t read;//块读序号
    uint32_t used; //已使用的块数量
    uint32_t blk_size;//块大小
    ring_fifo_mutex_t mutex;//互斥锁
    ring_fifo_sem_t sem;//写信号量
} ring_fifo_t;

void ring_fifo_reset(ring_fifo_t *fifo);
uint32_t ring_fifo_size(ring_fifo_t *fifo);
uint32_t ring_fifo_len(ring_fifo_t *fifo);
uint32_t ring_fifo_avail(ring_fifo_t *fifo);
bool ring_fifo_is_empty(ring_fifo_t *fifo);
bool ring_fifo_is_full(ring_fifo_t *fifo);

/* write to block ringbuffer */
uint32_t ring_fifo_write(ring_fifo_t *fifo, const void *in, uint32_t len);
uint32_t ring_fifo_write_force(ring_fifo_t *fifo, void *datptr, uint32_t len);
/* read to block ringbuffer */
uint32_t ring_fifo_read(ring_fifo_t *fifo, void *outbuf, uint32_t len);
/* probe read to block ringbuffer */
uint32_t ring_fifo_read_probe(ring_fifo_t *fifo, void *outbuf, uint32_t len);
/* move to another block ringbuffer */
uint32_t ring_fifo_move(ring_fifo_t *fifo_in, ring_fifo_t *fifo_out);

/* init block ringbuffer */
void ring_fifo_init(ring_fifo_t *fifo, uint32_t size, uint32_t blk_size);

#ifdef __cplusplus
}
#endif

#endif /* _RING_FIFO_H_ */
