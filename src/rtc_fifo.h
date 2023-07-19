#ifndef _RTC_FIFO_H_
#define _RTC_FIFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <aos/kernel.h>
#include <aos/cli.h>

// os port
typedef aos_mutex_t rtc_fifo_mutex_t;
typedef aos_sem_t rtc_fifo_sem_t;
#define RTC_FIFO_LOCK(fifo) aos_mutex_lock(&fifo->mutex, AOS_WAIT_FOREVER)
#define RTC_FIFO_UNLOCK(fifo) aos_mutex_unlock(&fifo->mutex)
#define RTC_FIFO_MUTEX_INIT(fifo) aos_mutex_new(&fifo->mutex)
#define RTC_FIFO_CALLOC(nums, size) aos_calloc_check(nums, size);
#define RTC_FIFO_SEM_INIT(fifo) aos_sem_new(&fifo->sem, 0)

// common
typedef struct {
    void *buffer;
    uint32_t size; // 缓冲区支持的最大块数量
    uint32_t write; //块写序号
    uint32_t read;//块读序号
    uint32_t used; //已使用的块数量
    uint32_t blk_size;//块大小
    rtc_fifo_mutex_t mutex;//互斥锁
    rtc_fifo_sem_t sem;//写信号量
} rtc_fifo_t;

void rtc_fifo_reset(rtc_fifo_t *fifo);
uint32_t rtc_fifo_size(rtc_fifo_t *fifo);
uint32_t rtc_fifo_len(rtc_fifo_t *fifo);
uint32_t rtc_fifo_avail(rtc_fifo_t *fifo);
bool rtc_fifo_is_empty(rtc_fifo_t *fifo);
bool rtc_fifo_is_full(rtc_fifo_t *fifo);

/* write to block ringbuffer */
uint32_t rtc_fifo_write(rtc_fifo_t *fifo, const void *in, uint32_t len);
uint32_t rtc_fifo_write_force(rtc_fifo_t *fifo, void *datptr, uint32_t len);
/* read to block ringbuffer */
uint32_t rtc_fifo_read(rtc_fifo_t *fifo, void *outbuf, uint32_t len);
/* probe read to block ringbuffer */
uint32_t rtc_fifo_read_probe(rtc_fifo_t *fifo, void *outbuf, uint32_t len);
/* move to another block ringbuffer */
uint32_t rtc_fifo_move(rtc_fifo_t *fifo_in, rtc_fifo_t *fifo_out);

/* init block ringbuffer */
void rtc_fifo_init(rtc_fifo_t *fifo, uint32_t size, uint32_t blk_size);

#ifdef __cplusplus
}
#endif

#endif /* _RTC_FIFO_H_ */
