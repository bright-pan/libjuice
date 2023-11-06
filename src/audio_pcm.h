#ifndef __AUDIO_PCM_H__
#define __AUDIO_PCM_H__

#include <media_audio.h>
#include <alsa/pcm.h>
#include <cviaudio_algo_interface.h>
#include <cvi_comm_aio.h>


#define ENABLE_3A_DATA 1

#define MIC_AUDIO_LEFT 0
#define MIC_AUDIO_RIGHT 1

#define RTP_VIDEO_ENC_INTERVAL 10 //ms

#define PCM_CAPTURE_DEVICE_NAME "pcmC0"
#define PCM_CAPTURE_DEVICE_STREAM AOS_PCM_STREAM_CAPTURE

#define PCM_CAPTURE_INPUT_GAIN 12
#define PCM_CAPTURE_HW_PARAMS_DIR 1
#define PCM_CAPTURE_HW_PARAMS_BIT_DEPTH 16 // sample depth
#define PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES (PCM_CAPTURE_HW_PARAMS_BIT_DEPTH / 8) // sample depth bytes
#define PCM_CAPTURE_HW_PARAMS_CHANNEL 2 // sample channel
#define PCM_CAPTURE_HW_PARAMS_RATE 8000 // sample rate
#define PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE (320)// 25fps(40ms/packet) sample window size
#define PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES (PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES * PCM_CAPTURE_HW_PARAMS_CHANNEL)
#define PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE (PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * 2) // sample window buffer size
#define PCM_CAPTURE_HW_PARAMS_BUFFER_BYTES (PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES * PCM_CAPTURE_HW_PARAMS_CHANNEL)

#define PCM_CAPTURE_PERIOD_TIMEOUT (1000 * PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE / PCM_CAPTURE_HW_PARAMS_RATE)

#define RTP_AUDIO_ENC_INTERVAL (PCM_CAPTURE_PERIOD_TIMEOUT / 2) //ms

#define CVIAUDIO_CHANNEL PCM_CAPTURE_HW_PARAMS_CHANNEL
#define CVIAUDIO_PER_SAMPLE PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES
#define CVIAUDIO_AEC_LENGTH 160


#define PCM_PLAY_DEVICE_NAME "pcmP0"
#define PCM_PLAY_DEVICE_STREAM AOS_PCM_STREAM_PLAYBACK

#define RTP_AUDIO_DEC_PERIOD_SIZE 160

#define PCM_PLAY_OUTPUT_GAIN 20
#define PCM_PLAY_HW_PARAMS_DIR 0
#define PCM_PLAY_HW_PARAMS_BIT_DEPTH 16 // play depth
#define PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES (PCM_PLAY_HW_PARAMS_BIT_DEPTH / 8) // play depth bytes
#define PCM_PLAY_HW_PARAMS_CHANNEL 2
#define PCM_PLAY_HW_PARAMS_RATE 8000
#define PCM_PLAY_HW_PARAMS_PERIOD_SIZE 160 // 10fps(100ms/packet) play window size
#define PCM_PLAY_HW_PARAMS_PERIOD_BYTES (PCM_PLAY_HW_PARAMS_PERIOD_SIZE * PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES * PCM_PLAY_HW_PARAMS_CHANNEL)
#define PCM_PLAY_HW_PARAMS_BUFFER_SIZE (PCM_PLAY_HW_PARAMS_PERIOD_SIZE * 2) // play window buuffer size
#define PCM_PLAY_HW_PARAMS_BUFFER_BYTES (PCM_PLAY_HW_PARAMS_BUFFER_SIZE * PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES * PCM_PLAY_HW_PARAMS_CHANNEL)

#define PCM_PLAY_PERIOD_TIMEOUT (1000 * PCM_PLAY_HW_PARAMS_PERIOD_SIZE / PCM_PLAY_HW_PARAMS_RATE)

#define RTP_AUDIO_DEC_PERIOD_PACKET_SIZE (PCM_PLAY_HW_PARAMS_PERIOD_SIZE / RTP_AUDIO_DEC_PERIOD_SIZE)

#define RTP_AUDIO_DEC_INTERVAL (PCM_PLAY_PERIOD_TIMEOUT / 2) //ms

typedef struct {
    aos_pcm_t *handle;
    int dir;
    unsigned int rate;
    int bit_depth;
    int period_size;
    int buffer_size;
    int channel;
} pcm_t;

typedef struct {
    pcm_t *pcm;

    AI_TALKVQE_CONFIG_S stVqeConfig;
    void *pssp_handle;

    short *mic_in;
    short *ref_in;
    short *datain;
    short *dataout;
} audio_t;

typedef enum {
    AUDIO_MULTIPLITER_TYPE_REF = 0,
    AUDIO_MULTIPLITER_TYPE_SPK = 1
} audio_multiplier_type_t;

#define AUDIO_MULTIPLITER_VALUE_REF 6 // 6db
#define AUDIO_MULTIPLITER_VALUE_SPK 2 // 2db

void audio_3a_init(audio_t *audio);
int pcm_capture_init(pcm_t *pcm);
int pcm_play_init(pcm_t *pcm);
int pcm_init(pcm_t *pcm, char *name, aos_pcm_stream_t stream);
void audio_capture_init(audio_t *audio, pcm_t *pcm);
void audio_play_init(audio_t *audio, pcm_t *pcm);
int audio_mono2stereo(const short *src_audio, int frames, short *dst_audio);
int audio_stereo2mono(const short *src_audio, int frames, short *dst_audio, int channel_num);
void audio_3a_process(audio_t *audio, char *pMicIn, int frameSize, char *pMicOut, int frameDataSize);

void audio_capture_set_gain(audio_t *audio, int again, int dgain);
void audio_play_set_gain(audio_t *audio, int again, int dgain);
void audio_set_multiplier(audio_multiplier_type_t type, int db);

#endif
