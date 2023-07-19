#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "rtc_fifo.h"

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

/**
  * \brief  Removes the entire FIFO contents.
  * \param  [in] fifo: The fifo to be emptied.
  * \return None.
  */
void rtc_fifo_reset(rtc_fifo_t *fifo)
{
    RTC_FIFO_LOCK(fifo);
    fifo->write = fifo->read = 0;
    fifo->used = 0;
    RTC_FIFO_UNLOCK(fifo);
}

/**
  * \brief  Returns the size of the FIFO in blocks.
  * \param  [in] fifo: The fifo to be used.
  * \return The size of the FIFO.
  */
uint32_t rtc_fifo_size(rtc_fifo_t *fifo)
{
    return fifo->size;
}

/**
  * \brief  Returns the number of used block in the FIFO.
  * \param  [in] fifo: The fifo to be used.
  * \return The number of used blocks.
  */
uint32_t rtc_fifo_len(rtc_fifo_t *fifo)
{
    return fifo->used;
}

/**
  * \brief  Returns the number of block available in the FIFO.
  * \param  [in] fifo: The fifo to be used.
  * \return The number of block available.
  */
uint32_t rtc_fifo_avail(rtc_fifo_t *fifo)
{
    return rtc_fifo_size(fifo) - rtc_fifo_len(fifo);
}

/**
  * \brief  Is the FIFO empty?
  * \param  [in] fifo: The fifo to be used.
  * \retval true:      Yes.
  * \retval false:     No.
  */
bool rtc_fifo_is_empty(rtc_fifo_t *fifo)
{
    return rtc_fifo_len(fifo) == 0;
}

/**
  * \brief  Is the FIFO full?
  * \param  [in] fifo: The fifo to be used.
  * \retval true:      Yes.
  * \retval false:     No.
  */
bool rtc_fifo_is_full(rtc_fifo_t *fifo)
{
    return rtc_fifo_avail(fifo) == 0;
}

/**
  * \brief  Puts some data into the FIFO.
  * \param  [in] fifo: The fifo to be used.
  * \param  [in] in:   The data to be added.
  * \param  [in] len:  The length of the block to be added.
  * \return The number of bytes copied.
  * \note   This function copies at most @len blocks from the @in into
  *         the FIFO depending on the free block space, and returns the number
  *         of blocks copied.
  */
uint32_t rtc_fifo_write(rtc_fifo_t *fifo, const void *datptr, uint32_t len)
{
    uint32_t writelen = 0, tmplen = 0;

    if(rtc_fifo_is_full(fifo))
        return 0;

    tmplen = fifo->size - fifo->used;
    writelen = tmplen > len ? len : tmplen;

    if(fifo->write < fifo->read) {
        memcpy(fifo->buffer + fifo->write * fifo->blk_size, datptr, writelen * fifo->blk_size);
    } else {
        tmplen = fifo->size - fifo->write;
        if(writelen <= tmplen) {
            memcpy((uint8_t*)fifo->buffer + fifo->write * fifo->blk_size,
                   (void *)datptr, writelen * fifo->blk_size);
        } else {
            memcpy((uint8_t*)fifo->buffer + fifo->write * fifo->blk_size,
                   (void *)datptr, tmplen * fifo->blk_size);
            memcpy((void *)fifo->buffer, (uint8_t *)datptr + tmplen * fifo->blk_size,
                   (writelen - tmplen) * fifo->blk_size);
        }
    }

    RTC_FIFO_LOCK(fifo);
    fifo->write = (fifo->write + writelen) % fifo->size;
    fifo->used += writelen;
    RTC_FIFO_UNLOCK(fifo);

    return writelen;
}

/**
  * \brief  Gets some data from the FIFO.
  * \param  [in] fifo: The fifo to be used.
  * \param  [in] out:  Where the data must be copied.
  * \param  [in] len:  The size of the destination buffer.
  * \return The number of copied blocks.
  * \note   This function copies at most @len blocks from the FIFO into
  *         the @out and returns the number of copied blocks.
  */
uint32_t rtc_fifo_read(rtc_fifo_t *fifo, void *outbuf, uint32_t len)
{
    uint32_t readlen = 0, tmplen = 0;
    if(rtc_fifo_is_empty(fifo))
        return 0;

    uint32_t used = fifo->used;
    readlen = len > used ? used : len;
    tmplen = fifo->size - fifo->read;

    if(NULL != outbuf) {
        if(readlen <= tmplen) {
            memcpy((void *)outbuf, (uint8_t *)fifo->buffer + fifo->read * fifo->blk_size,
                   readlen * fifo->blk_size);
        } else {
            memcpy((void *)outbuf, (uint8_t *)fifo->buffer + fifo->read * fifo->blk_size,
                   tmplen * fifo->blk_size);
            memcpy((uint8_t *)outbuf + tmplen * fifo->blk_size, (void*)fifo->buffer,
                   (readlen - tmplen) * fifo->blk_size);
        }
    }

    RTC_FIFO_LOCK(fifo);
    fifo->read = (fifo->read + readlen) % fifo->size;
    fifo->used -= readlen;
    RTC_FIFO_UNLOCK(fifo);

    return readlen;
}


/**
  * \brief  probe get some data from the FIFO.
  * \param  [in] fifo: The fifo to be used.
  * \param  [in] out:  Where the data must be copied.
  * \param  [in] len:  The size of the destination buffer.
  * \return The number of copied blocks.
  * \note   This function copies at most @len blocks from the FIFO into
  *         the @out and returns the number of copied blocks.
  */
uint32_t rtc_fifo_read_probe(rtc_fifo_t *fifo, void *outbuf, uint32_t len)
{
    uint32_t readlen = 0, tmplen = 0;
    if(rtc_fifo_is_empty(fifo))
        return 0;

    uint32_t used = fifo->used;
    readlen = len > used ? used : len;
    tmplen = fifo->size - fifo->read;

    if(NULL != outbuf) {
        if(readlen <= tmplen) {
            memcpy((void *)outbuf, (uint8_t *)fifo->buffer + fifo->read * fifo->blk_size,
                   readlen * fifo->blk_size);
        } else {
            memcpy((void *)outbuf, (uint8_t *)fifo->buffer + fifo->read * fifo->blk_size,
                   tmplen * fifo->blk_size);
            memcpy((uint8_t *)outbuf + tmplen * fifo->blk_size, (void*)fifo->buffer,
                   (readlen - tmplen) * fifo->blk_size);
        }
    }
    /*
    RTC_FIFO_LOCK(fifo);
    fifo->read = (fifo->read + readlen) % fifo->size;
    fifo->used -= readlen;
    RTC_FIFO_UNLOCK(fifo);
    */
    return readlen;
}


/**
  * \brief  Move FIFO buffer to another FIFO.
  * \param  [in] fifo_in: The fifo to be used.
  * \param  [in] fifo_out: The fifo to be used.
  * \return The number of copied blocks.
  * \note   This function copies at most @len bytes from the FIFO into
  *         the @out and returns the number of copied blocks.
  */
uint32_t rtc_fifo_move(rtc_fifo_t *fifo_in, rtc_fifo_t *fifo_out)
{
    uint32_t readlen = 0, tmplen_out = 0;
    if(rtc_fifo_is_empty(fifo_out))
        return 0;

    int len = rtc_fifo_avail(fifo_in);

    uint32_t used = fifo_out->used;
    readlen = len > used ? used : len;
    tmplen_out = fifo_out->size - fifo_out->read;

    if(readlen <= tmplen_out) {
        rtc_fifo_write(fifo_in, (uint8_t *)fifo_out->buffer + fifo_out->read * fifo_out->blk_size, readlen);
    } else {
        rtc_fifo_write(fifo_in, (int8_t *)fifo_out->buffer + fifo_out->read * fifo_out->blk_size, tmplen_out);
        rtc_fifo_write(fifo_in, (void*)fifo_out->buffer, readlen - tmplen_out);
    }

    RTC_FIFO_LOCK(fifo_out);
    fifo_out->read = (fifo_out->read + readlen) % fifo_out->size;
    fifo_out->used -= readlen;
    RTC_FIFO_UNLOCK(fifo_out);

    return readlen;
}

/**
  * \brief  Puts some data into the FIFO with force.
  * \param  [in] fifo: The fifo to be used.
  * \param  [in] in:   The data to be added.
  * \param  [in] len:  The length of the data to be added.
  * \return The number of blocks copied.
  * \note   This function copies at most @len blocks from the @in into
  *         the FIFO depending on the free block space, and returns the number
  *         of block copied.
  */
uint32_t rtc_fifo_write_force(rtc_fifo_t *fifo, void *datptr, uint32_t len) {
    uint32_t avail = rtc_fifo_avail(fifo);
    uint32_t _ring = len / fifo->size;
    uint32_t writelen = 0;

    if (_ring > 0) {
        rtc_fifo_reset(fifo);
        datptr = (uint8_t *)datptr + (len - fifo->size) * fifo->blk_size;
        writelen = rtc_fifo_write(fifo, datptr, fifo->size);
    } else {
        uint32_t _len = len % fifo->size;
        if (avail >= _len) {
            writelen = rtc_fifo_write(fifo, datptr, _len);
        } else {
            rtc_fifo_read(fifo, NULL, _len - avail);
            writelen = rtc_fifo_write(fifo, datptr, _len);
        }
    }

    return writelen;
}

/**
  * \brief  new FIFO initialize.
  * \param  [in] size: The fifo block nums.
  * \param  [in] blk_size: The block size.
  * \return None.
  * \note   This function initialize new FIFO for block.
  */
void rtc_fifo_init(rtc_fifo_t *fifo, uint32_t size, uint32_t blk_size) {
    fifo->buffer = RTC_FIFO_CALLOC(size, blk_size);
    fifo->size = size;
    fifo->blk_size = blk_size;
    fifo->write = fifo->read = 0;
    fifo->used = 0;
    RTC_FIFO_MUTEX_INIT(fifo);
    RTC_FIFO_SEM_INIT(fifo);
}

#if 0

rtc_fifo_t fifo_test;

static void fifo_init(int argc, char **argv) {
    rtc_fifo_init(&fifo_test, 20, 1);
}

static void fifo_write(int argc, char **argv) {
    rtc_fifo_write(&fifo_test, argv[1], atoi(argv[2]));
}

static void fifo_write_force(int argc, char **argv) {
    rtc_fifo_write_force(&fifo_test, argv[1], atoi(argv[2]));
}

static void fifo_read(int argc, char **argv) {
    char buf[256];
    memset(buf, '\0', 256);
    rtc_fifo_read(&fifo_test, buf, atoi(argv[1]));
    LANGO_LOG_INFO(buf);
}

ALIOS_CLI_CMD_REGISTER(fifo_init, fifo_init, fifo_init);
ALIOS_CLI_CMD_REGISTER(fifo_write, fifo_write, fifo_write);
ALIOS_CLI_CMD_REGISTER(fifo_write_force, fifo_write_force, fifo_write_force);
ALIOS_CLI_CMD_REGISTER(fifo_read, fifo_read, fifo_read);

#endif
