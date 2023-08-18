#include "rtp_frame.h"
#include "aos/kernel.h"
#include "log.h"


#define RTP_FRAME_DELETE_INTERVAL 10 //1000/30)
#define RTP_FRAME_DELETE_COUNT 3

static rtp_frame_t *rtp_frames = NULL;

static aos_timer_t rtp_frame_delete_timer;

static int by_seq_number(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->seq_number - b->seq_number);
}

static int by_bytes(const rtp_frame_t *a, const rtp_frame_t *b)
{
    return (a->bytes - b->bytes);
}

int rtp_frame_add(int seq_number, const char *packet, int bytes)
{
    int ret = -1;
    rtp_frame_t *frame;

    HASH_FIND_INT(rtp_frames, &seq_number, frame);  /* seq_number already in the hash? */
    if (frame == NULL) {
        frame = (rtp_frame_t *)uthash_malloc(sizeof(rtp_frame_t));
        if (frame) {
            frame->seq_number = seq_number;
            frame->packet = uthash_malloc(bytes);
            frame->bytes = bytes;
            frame->count = RTP_FRAME_DELETE_COUNT - 1;
            if (frame->packet) {
                memcpy(frame->packet, packet, bytes);
                HASH_ADD_INT(rtp_frames, seq_number, frame);  /* seq_number is the key field */
                ret = 0;
            } else {
                uthash_free(frame, 0);
            }
        }
    }
    return ret;
}

rtp_frame_t *rtp_frame_find(int seq_number)
{
    rtp_frame_t *frame;

    HASH_FIND_INT(rtp_frames, &seq_number, frame);  /* frame: output pointer */
    return frame;
}

void rtp_frame_delete(rtp_frame_t *frame)
{
    HASH_DEL(rtp_frames, frame);  /* frame: pointer to delete */
    uthash_free(frame->packet, 0);
    uthash_free(frame, 0);
}

void rtp_frame_delete_all(void)
{
    rtp_frame_t *frame;
    rtp_frame_t *tmp;

    HASH_ITER(hh, rtp_frames, frame, tmp) {
        rtp_frame_delete(frame);  /* delete it (users advances to next) */
    }
}

void rtp_frame_reset(void)
{
    rtp_frame_delete_all();
}

int rtp_frame_delete_by_seq_number(int seq_number)
{
    int ret = -1;
    rtp_frame_t *frame;

    frame = rtp_frame_find(seq_number);
    if (frame) {
        rtp_frame_delete(frame);
        ret = 0;
    }
    return ret;
}

int rtp_frame_count(void)
{
    return HASH_COUNT(rtp_frames);
}

void rtp_frame_sort_by_bytes(void)
{
    HASH_SORT(rtp_frames, by_bytes);
}

void rtp_frame_sort_by_seq_number(void)
{
    HASH_SORT(rtp_frames, by_seq_number);
}

static void rtp_frame_print(rtp_frame_t *frame)
{
    JLOG_INFO("----------------------------");
    JLOG_INFO_DUMP_HEX(frame->packet, frame->bytes, "seq_number %d: %d Bytes", frame->seq_number, frame->bytes);
}

void rtp_frame_print_by_seq_number(int seq_number)
{
    rtp_frame_t *frame;
    frame = rtp_frame_find(seq_number);
    rtp_frame_print(frame);
}

void rtp_frame_print_all(void)
{
    rtp_frame_t *frame;
    
    JLOG_INFO("rtp frame counts[%d]", rtp_frame_count());
    for (frame = rtp_frames; frame != NULL; frame = (rtp_frame_t *)(frame->hh.next)) {
        rtp_frame_print(frame);
    }
}

static void rtp_frame_delete_timer_handler(void *arg1, void* arg2)
{
    rtp_frame_t *frame;
    rtp_frame_t *tmp;

    HASH_ITER(hh, rtp_frames, frame, tmp) {
        //rtp_frame_print(frame);
        if (frame->count-- <= 0) {
            rtp_frame_delete(frame);  /* delete it (users advances to next) */
        }
    }
}

int rt_frame_delete_timer_init(int interval) {
    int ret;
    ret = aos_timer_new_ext(&rtp_frame_delete_timer, rtp_frame_delete_timer_handler,
                            NULL, interval, 1, 1);
    if (ret != 0) {
        JLOG_ERROR("rt_frame_delete_timer create failed");
    }
    return ret;
}

#include <aos/cli.h>

int test_rtpframe(int argc, char **argv)
{
    static int id = 1;
    rtp_frame_t *s;
    int temp;
    if (argc < 2) {
        printf("%s 1 frame size - add frame size\n", argv[0]);
        printf("%s 2 id frame size - add or rename frame by id\n", argv[0]);
        printf("%s 3 id - find frame\n", argv[0]);
        printf("%s 4 id - delete frame\n", argv[0]);
        printf("%s 5 - delete all frame\n", argv[0]);
        printf("%s 6 - sort items by bytes\n", argv[0]);
        printf("%s 7 - sort items by id\n", argv[0]);
        printf("%s 8 - print frame\n", argv[0]);
        printf("%s 9 - count frame\n", argv[0]);
        printf("%s 10 interval - start delete timer\n", argv[0]);
    } else {
        switch (atoi(argv[1])) {
            case 1:
                rtp_frame_add(id++, argv[2], atoi(argv[3]));
                break;
            case 2:
                temp = atoi(argv[2]);
                rtp_frame_add(temp, argv[3], atoi(argv[4]));
                break;
            case 3:
                s = rtp_frame_find(atoi(argv[2]));
                printf("packet: %s\n", s ? s->packet : "unknown");
                break;
            case 4:
                s = rtp_frame_find(atoi(argv[2]));
                if (s) {
                    rtp_frame_delete(s);
                } else {
                    printf("id unknown\n");
                }
                break;
            case 5:
                rtp_frame_delete_all();
                break;
            case 6:
                rtp_frame_sort_by_bytes();
                break;
            case 7:
                rtp_frame_sort_by_seq_number();
                break;
            case 8:
                rtp_frame_print_all();
                break;
            case 9:
                temp = rtp_frame_count();
                printf("there are %d frame\n", temp);
                break;
            case 10:
                rt_frame_delete_timer_init(atoi(argv[2]));
                break;
        }
    }
    return 0;
}

ALIOS_CLI_CMD_REGISTER(test_rtpframe, test_rtpframe, test_rtpframe);