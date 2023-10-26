#include <cvi_venc.h>
#include <media_video.h>

#include <media_audio.h>
#include <alsa/pcm.h>
#include <cviaudio_algo_interface.h>
#include <cvi_comm_aio.h>
#include <g711.h>
#include <g711_table.h>
#include "platform_http.h"
#include <lango_default_define.h>

#include "rtp.h"
#include "rtp_enc.h"
#include "peer_connection.h"
#include "thread.h"
#include "audio_demo.h"
#include "audio_pcm.h"


#define PCM_REC_TIME_MAX 60
#define PCM_REC_PERIOD_NUMS_PER_SECOND (1000 / PCM_CAPTURE_PERIOD_TIMEOUT)
#define PCM_REC_BUFFER_BYTES (PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES * PCM_REC_PERIOD_NUMS_PER_SECOND * PCM_REC_TIME_MAX)
#define PCM_REC_BUFFER_BYTES_PER_SECOND (PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES * PCM_REC_PERIOD_NUMS_PER_SECOND)

#define PCM_REC_PUSH_URL "http://192.168.1.186:5000/pcm"

static char pcm_rec_buf[PCM_REC_BUFFER_BYTES];
static char pcm_rec_enc_buf[PCM_REC_BUFFER_BYTES];
static int pcm_rec_index = 0;
static int pcm_rec_time = PCM_REC_TIME_MAX;
static int pcm_3a_process_flag = 0;
static pcm_t pcm_capture;
static audio_t audio_capture;

static pcm_t pcm_play;
static audio_t audio_play;

thread_t test_audio_thread;


extern int Lango_Set_AudioOutVol(int again, int dgain);
extern int aos_pcm_write_wait_complete(aos_pcm_t *pcm, int timeout);


static void *test_audio_thread_entry(void *param) {
    int ret = 0;
    peer_connection_t *pc = param;
    audio_t *capture = &audio_capture;
    audio_t *play = &audio_play;
    char pcm_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];
    char pcm_enc_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];

    thread_set_name_self("test_audio");
    // audio initialize
    LG_media_audio_init();
    // pcm device init
    audio_capture_init(capture, &pcm_capture);
    audio_play_init(play, &pcm_play);

    // audio demo init
    // audio_demo_init(AUDIO_DEMO_LENGTH, AUDIO_DEMO_CHANNEL_NUM, AUDIO_DEMO_BIT_DEPTH);

    while (1) {
        ret = aos_pcm_readi(capture->pcm->handle, pcm_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
        // ret = audio_demo_readi((unsigned char *)pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
        if (ret > 0) {
            if (pcm_3a_process_flag) {// CVI 3a process
                audio_3a_process(capture, pcm_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, pcm_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
            } else {
                memcpy(pcm_enc_buffer, pcm_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
            }
            // // audio_stereo2mono((short *)pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, (short *)pcm_capture_buffer, MIC_AUDIO_LEFT);
            ret = aos_pcm_writei(play->pcm->handle, pcm_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            if(pcm_rec_index + PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES <= pcm_rec_time * PCM_REC_BUFFER_BYTES_PER_SECOND) {
                memcpy(pcm_rec_enc_buf + pcm_rec_index, pcm_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
                memcpy(pcm_rec_buf + pcm_rec_index, pcm_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
                pcm_rec_index += PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES;
            }
            aos_pcm_write_wait_complete(play->pcm->handle, 20);
        } else {
            usleep(RTP_AUDIO_ENC_INTERVAL*1000);
        }
    }
    pthread_exit(&pc->rtp_audio_enc_loop_flag);
    return NULL;
}

int test_audio_thread_init(void) {
    int ret = -1;
    thread_attr_t attr;

    thread_attr_init(&attr, 33, 10*1024);
    ret = thread_init_ex(&test_audio_thread, &attr, test_audio_thread_entry, NULL);
    if (ret != 0) {
        JLOG_ERROR("test_audio_thread thread created failure!");
    } else {
        JLOG_INFO("test_audio_thread thread created!");
    }
    return ret;
}

#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>
#include <lwip/stats.h>

static void test_audio_usage(int argc, char **argv) {
    JLOG_ERROR("Usage: %s init\n", argv[0]);
    JLOG_ERROR("Usage: %s capture_gain again dgain\n", argv[0]);
    JLOG_ERROR("Usage: %s play_gain again dgain\n", argv[0]);
    JLOG_ERROR("Usage: %s rec_stats\n", argv[0]);
    JLOG_ERROR("Usage: %s rec_time [seconds]\n", argv[0]);
    JLOG_ERROR("Usage: %s rec_reset\n", argv[0]);
    JLOG_ERROR("Usage: %s rec_3a [0/1]\n", argv[0]);
    JLOG_ERROR("Usage: %s rec_push [0/1]\n", argv[0]);
}

static void test_audio(int argc, char **argv) {
    
    audio_t *capture = &audio_capture;
    audio_t *play = &audio_play;

    if (argc < 2) {
        test_audio_usage(argc, argv);
        return;
    }

    if (strstr(argv[1], "init")) {
        test_audio_thread_init();
    } else if (strstr(argv[1], "play_gain")) {
        audio_play_set_gain(play, atoi(argv[2]), atoi(argv[3]));
    } else if (strstr(argv[1], "capture_gain")) {
        audio_capture_set_gain(capture, atoi(argv[2]), atoi(argv[3]));
    } else if (strstr(argv[1], "rec_stats")) {
        if (pcm_rec_index >= pcm_rec_time * PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES * 50) {
            JLOG_WARN("pcm_rec_index is full");
        }
        JLOG_INFO("pcm_rec_index = %d", pcm_rec_index);
    } else if (strstr(argv[1], "rec_time")) {
        int rec_time = atoi(argv[2]);
        if (rec_time < PCM_REC_TIME_MAX) {
            pcm_rec_time = rec_time;
            JLOG_INFO("pcm_rec_time = %d", pcm_rec_time);
        } else {
            JLOG_ERROR("rec_time[%d] > PCM_REC_TIME_MAX[%d]", rec_time, PCM_REC_TIME_MAX);
        }
    } else if (strstr(argv[1], "rec_mono_push")) {
        int frame_size = (pcm_rec_index / PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES) * PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE / 2;
        char *buf = malloc(frame_size * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES);
        int frame_bytes = 2 * audio_stereo2mono((short *)pcm_rec_buf, frame_size, (short *)buf, MIC_AUDIO_LEFT);
        JLOG_INFO("push picture host_addr:%s", PCM_REC_PUSH_URL);
        http_postpic(buf, frame_bytes, PCM_REC_PUSH_URL, "12345678", "0", "jpg");
        free(buf);
    } else if (strstr(argv[1], "rec_3a")) {
        pcm_3a_process_flag = atoi(argv[2]);
    } else if (strstr(argv[1], "rec_reset")) {
        pcm_rec_index = 0;
    } else if (strstr(argv[1], "rec_push")) {
        JLOG_INFO("push picture host_addr:%s", PCM_REC_PUSH_URL);
        if (atoi(argv[2])) {
            http_postpic(pcm_rec_enc_buf, pcm_rec_index, PCM_REC_PUSH_URL, "12345678", "0", "jpg");
        } else {
            http_postpic(pcm_rec_buf, pcm_rec_index, PCM_REC_PUSH_URL, "12345678", "0", "jpg");
        }
    } else {
        test_audio_usage(argc, argv);
    }
}

ALIOS_CLI_CMD_REGISTER(test_audio, test_audio, test_audio);

#endif