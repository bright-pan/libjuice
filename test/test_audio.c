#include <cvi_venc.h>
#include <media_video.h>

#include <media_audio.h>
#include <alsa/pcm.h>
#include <cviaudio_algo_interface.h>
#include <cvi_comm_aio.h>
#include <g711.h>
#include <g711_table.h>

#include <lango_default_define.h>

#include "rtp.h"
#include "rtp_enc.h"
#include "peer_connection.h"
#include "thread.h"
#include "audio_demo.h"
#include "audio_pcm.h"


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
            // CVI 3a process
            audio_3a_process(capture, pcm_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, pcm_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
            // audio_stereo2mono((short *)pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, (short *)pcm_capture_buffer, MIC_AUDIO_LEFT);
            ret = aos_pcm_writei(play->pcm->handle, pcm_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            aos_pcm_write_wait_complete(play->pcm->handle, PCM_PLAY_TIMOUT_MS);
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
    } else {
        test_audio_usage(argc, argv);
    }
}

ALIOS_CLI_CMD_REGISTER(test_audio, test_audio, test_audio);

#endif