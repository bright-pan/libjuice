#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include "packet.h"
#include "log.h"

typedef struct {
    unsigned int data_size;
    void* data;
} packet_frame_t;

/*
static inline int _fifo_read(packet_fifo_t *fifo, packet_frame_t *frame) {
    int ret = -1;

    if (ring_fifo_read(fifo, frame, 1) == 1) {
        ret = frame->data_size;
    }
    return ret;
}

static inline int _fifo_write(packet_fifo_t *fifo, packet_frame_t *frame) {
    int ret = -1;
    packet_frame_t _frame;

    // clear space if full
    if (ring_fifo_is_full(fifo) && ring_fifo_read(fifo, &_frame, 1) == 1) {
        if (_frame.data) {
            RING_FIFO_FREE(_frame.data);
        }
    }
    // malloc failed
    _frame.data = RING_FIFO_MALLOC(frame->data_size);
    if (_frame.data == NULL) {
        JLOG_ERROR("fifo malloc failed");
        //mempool_trace();
        goto ERROR;
    }
    // write data
    memcpy(_frame.data, frame->data, frame->data_size);
    _frame.data_size = frame->data_size;
    if (ring_fifo_write(fifo, &_frame, 1) == 1) {
        ret = frame->data_size;
    } else {
        RING_FIFO_FREE(_frame.data);
    }
ERROR:
    return ret;
}

int _packet_fifo_read(packet_fifo_t *fifo, packet_frame_t *frame) {
    int ret = -1;
    RING_FIFO_LOCK(fifo);
    ret = _fifo_read(fifo, frame);
    RING_FIFO_UNLOCK(fifo);
    return ret;
}

int packet_fifo_write(packet_fifo_t *fifo, packet_frame_t *frame) {
    int ret = -1;
    RING_FIFO_LOCK(fifo);
    ret = _fifo_write(fifo, frame);
    RING_FIFO_UNLOCK(fifo);
    return ret;
}
*/

static inline int _fifo_write(packet_fifo_t *fifo, void *data, size_t size) {
    int ret = -1;
    packet_frame_t _frame;

    RING_FIFO_LOCK(fifo);
    // malloc failed
    _frame.data = RING_FIFO_MALLOC(size);
    if (_frame.data == NULL) {
        JLOG_ERROR("fifo malloc failed");
        //mempool_trace();
        goto ERROR;
    }

    // clear space if full
    if (ring_fifo_is_full(fifo) && ring_fifo_read(fifo, &_frame, 1) == 1) {
        if (_frame.data) {
            RING_FIFO_FREE(_frame.data);
        }
    }
    // write data
    memcpy(_frame.data, data, size);
    _frame.data_size = size;
    if (ring_fifo_write(fifo, &_frame, 1) == 1) {
        ret = size;
    } else {
        RING_FIFO_FREE(_frame.data);
    }
ERROR:
    RING_FIFO_UNLOCK(fifo);
    return ret;
}

int packet_fifo_write(packet_fifo_t *fifo, void *data, size_t size) {
    return _fifo_write(fifo, data, size);
}

static inline int _fifo_read(packet_fifo_t *fifo, void *data, size_t size, uint32_t is_muti) {
    int read_size = 0;
    int need_size = 0;
    packet_frame_t _frame;

    RING_FIFO_LOCK(fifo);
    do {
        if (ring_fifo_read(fifo, &_frame, 1) == 1) {
            need_size = size - read_size;
            if (need_size >= _frame.data_size) {
                memcpy(data + read_size, _frame.data + read_size, _frame.data_size);
                read_size += _frame.data_size;
            } else {
                memcpy(data + read_size, _frame.data + read_size, need_size);
                read_size += need_size;
            }
            RING_FIFO_FREE(_frame.data);
            if (read_size >= size) {
                break;
            }
        } else {
            break;
        }
    } while(is_muti);
    RING_FIFO_UNLOCK(fifo);

    if (read_size > 0) {
        return read_size;
    } else {
        return -1;
    }
}

int packet_fifo_read(packet_fifo_t *fifo, void *data, size_t size) {
    return _fifo_read(fifo, data, size, 0);
}

int packet_fifo_read_stream(packet_fifo_t *fifo, void *data, size_t size) {
    return _fifo_read(fifo, data, size, 1);
}


void packet_fifo_reset(packet_fifo_t *fifo) {
    packet_frame_t _frame;
    RING_FIFO_LOCK(fifo);
    uint32_t length = ring_fifo_len(fifo);
    while(length-- > 0) {
        if (ring_fifo_read(fifo, &_frame, 1) == 1) {
            if (_frame.data) {
                RING_FIFO_FREE(_frame.data);
            }
        }
    }
    RING_FIFO_UNLOCK(fifo);
}

void packet_fifo_clear(packet_fifo_t *fifo, uint32_t size) {
    packet_frame_t _frame;
    RING_FIFO_LOCK(fifo);
    uint32_t length = ring_fifo_len(fifo);
    length = length > size ? size : length;
    while(length-- > 0) {
        if (ring_fifo_read(fifo, &_frame, 1) == 1) {
            if (_frame.data) {
                RING_FIFO_FREE(_frame.data);
            }
        }
    }
    RING_FIFO_UNLOCK(fifo);
}
/*
void packet_fifo_clear_until_iframe(packet_fifo_t *fifo, uint32_t size) {
    RING_FIFO_LOCK(fifo);
    packet_frame_t _frame;
    uint32_t iframe_index = 0;
    uint32_t length = ring_fifo_len(fifo);
    length = length > size ? size : length;
    // get iframe index
    for (int _index=0; _index < length; _index++) {
        if (ring_fifo_read_probe(fifo, &_frame, 1) == 1) {
            if (_frame.type == packet_frame_tYPE_I) {
                iframe_index = _index;
            }
        }
    }
    if (iframe_index > 0) {
        LANGO_LOG_ERR("rtmp fifo clear size: %d", iframe_index);
    }
    // clear frame until iframe index
    while(iframe_index-- > 0) {
        if (ring_fifo_read_probe(fifo, &_frame, 1) == 1) {
            if (_frame.data) {
                RING_FIFO_FREE(_frame.data);
            }
        }
    }
    RING_FIFO_UNLOCK(fifo);
}
*/
uint32_t packet_fifo_size(packet_fifo_t *fifo) {
    uint32_t ret;
    RING_FIFO_LOCK(fifo);
    ret = ring_fifo_size(fifo);
    RING_FIFO_UNLOCK(fifo);
    return ret;
}

uint32_t packet_fifo_len(packet_fifo_t *fifo) {
    uint32_t ret;
    RING_FIFO_LOCK(fifo);
    ret = ring_fifo_len(fifo);
    RING_FIFO_UNLOCK(fifo);
    return ret;
}

uint32_t packet_fifo_avail(packet_fifo_t *fifo) {
    uint32_t ret;
    RING_FIFO_LOCK(fifo);
    ret = ring_fifo_avail(fifo);
    RING_FIFO_UNLOCK(fifo);
    return ret;
}


void packet_fifo_init(packet_fifo_t *fifo, size_t size) {
    ring_fifo_init(fifo, size, sizeof(packet_frame_t));
}
