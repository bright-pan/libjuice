#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <alsa/snd.h>
#include <alsa/pcm.h>
#include <alsa/mixer.h>
#include <devices/driver.h>
#include <drv/codec.h>
#include <math.h>
#include "log.h"
#include "audio_pcm.h"


int pcm_init(pcm_t *pcm, char *name, aos_pcm_stream_t stream) {
    int ret = -1;
    aos_pcm_hw_params_t *hw_params;
    aos_pcm_t *_handle = NULL;
    ret = aos_pcm_open(&pcm->handle, name, stream, 0);
    if (ret < 0) {
        JLOG_ERROR("pcm device %s open fail", name);
        return ret;
    }
    aos_pcm_hw_params_alloca(&hw_params);
    aos_pcm_hw_params_any(pcm->handle, hw_params);

    hw_params->period_size = pcm->period_size;
    hw_params->buffer_size = pcm->buffer_size;

    aos_pcm_hw_params_set_access(pcm->handle, hw_params, AOS_PCM_ACCESS_RW_INTERLEAVED);
    aos_pcm_hw_params_set_format(pcm->handle, hw_params, pcm->bit_depth);
    aos_pcm_hw_params_set_rate_near(pcm->handle, hw_params, &pcm->rate, &pcm->dir);
    aos_pcm_hw_params_set_channels(pcm->handle, hw_params, pcm->channel);
    aos_pcm_hw_params(pcm->handle, hw_params);
    //Lango_Set_AudioOutVol(30, 30);
    return 0;
}

int pcm_capture_init(pcm_t *pcm) {
    int ret = -1;

    pcm->rate = PCM_CAPTURE_HW_PARAMS_RATE;
    pcm->channel = PCM_CAPTURE_HW_PARAMS_CHANNEL;
    pcm->bit_depth = PCM_CAPTURE_HW_PARAMS_BIT_DEPTH;
    pcm->dir = PCM_CAPTURE_HW_PARAMS_DIR;
    pcm->period_size = PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE;
    pcm->buffer_size = PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE;

    ret = pcm_init(pcm, PCM_CAPTURE_DEVICE_NAME, PCM_CAPTURE_DEVICE_STREAM);

    return ret;
}

int pcm_play_init(pcm_t *pcm) {
    int ret = -1;

    pcm->rate = PCM_PLAY_HW_PARAMS_RATE;
    pcm->channel = PCM_PLAY_HW_PARAMS_CHANNEL;
    pcm->bit_depth = PCM_PLAY_HW_PARAMS_BIT_DEPTH;
    pcm->dir = PCM_PLAY_HW_PARAMS_DIR;
    pcm->period_size = PCM_PLAY_HW_PARAMS_PERIOD_SIZE;
    pcm->buffer_size = PCM_PLAY_HW_PARAMS_BUFFER_SIZE;

    ret = pcm_init(pcm, PCM_PLAY_DEVICE_NAME, PCM_PLAY_DEVICE_STREAM);

    return ret;
}

void audio_3a_init(audio_t *audio) {
    char pstrVersion[52];
    int channel = 2;/* only support 2chn*/
    int capture_rate = audio->pcm->rate;
    int AecLenByte = 0;

    AI_TALKVQE_CONFIG_S *pstVqeConfig = &audio->stVqeConfig;

    pstVqeConfig->para_client_config = 0;
    pstVqeConfig->u32OpenMask = AI_TALKVQE_MASK_AEC | AI_TALKVQE_MASK_ANR;// | AI_TALKVQE_MASK_AGC;//
    pstVqeConfig->s32WorkSampleRate = capture_rate;
    pstVqeConfig->s32RevMask = 0;
    pstVqeConfig->para_notch_freq = 0;
    /* AEC */
    pstVqeConfig->stAecCfg.para_aec_filter_len = 13;
    pstVqeConfig->stAecCfg.para_aes_std_thrd = 37;
    pstVqeConfig->stAecCfg.para_aes_supp_coeff = 60;

    pstVqeConfig->stAecDelayCfg.para_aec_init_filter_len = 13;
    pstVqeConfig->stAecDelayCfg.para_dg_target = 6;
    pstVqeConfig->stAecDelayCfg.para_delay_sample = 1;

    /* ANR */
    pstVqeConfig->stAnrCfg.para_nr_snr_coeff = 15;
    pstVqeConfig->stAnrCfg.para_nr_init_sile_time = 100;

    /* AGC */
    pstVqeConfig->stAgcCfg.para_agc_max_gain = 3;
    pstVqeConfig->stAgcCfg.para_agc_target_high = 2;
    pstVqeConfig->stAgcCfg.para_agc_target_low = 72;
    pstVqeConfig->stAgcCfg.para_agc_vad_ena = 1;

    CviAud_Algo_GetVersion(pstrVersion);
    JLOG_INFO("[cvi3aVersion:%s]\n", pstrVersion);

    audio->pssp_handle = CviAud_Algo_Init(pstVqeConfig->u32OpenMask, pstVqeConfig);
    if (!audio->pssp_handle) {
        JLOG_ERROR("cvi3a init fail\n");
        return;
    }

    AecLenByte = CVIAUDIO_AEC_LENGTH * channel * CVIAUDIO_PER_SAMPLE;
    audio->mic_in = juice_malloc(AecLenByte);
    audio->ref_in = juice_malloc(AecLenByte);
    audio->datain = juice_malloc(AecLenByte);
    audio->dataout = juice_malloc(AecLenByte);
}

void audio_capture_init(audio_t *audio, pcm_t *pcm) {
    pcm_capture_init(pcm);
    audio->pcm = pcm;
    audio_capture_set_gain(audio, PCM_CAPTURE_INPUT_GAIN, PCM_CAPTURE_INPUT_GAIN);
    audio_3a_init(audio);
}

void audio_play_init(audio_t *audio, pcm_t *pcm) {
    pcm_play_init(pcm);
    audio->pcm = pcm;
    audio_play_set_gain(audio, PCM_PLAY_OUTPUT_GAIN, PCM_PLAY_OUTPUT_GAIN);
}

int audio_mono2stereo(const short *src_audio, int frames, short *dst_audio)
{
    for (int i = 0; i < frames; i++)
    {
        dst_audio[2 * i] = src_audio[i];
        dst_audio[2 * i + 1] = src_audio[i];
    }
    return frames;
}

int audio_stereo2mono(const short *src_audio, int frames, short *dst_audio, int channel_num)
{
    for (int i = 0; i < frames; i++)
    {
        dst_audio[i] = src_audio[i * 2 + channel_num];
    }
    return frames;
}

void audio_3a_process(audio_t *audio, char *pMicIn, int frameSize, char *pMicOut, int frameDataSize)
{
    int RetframeLen = 0;
    int doIndex = 0,doDataIndex = 0;
    AI_TALKVQE_CONFIG_S *pstVqeConfig = &audio->stVqeConfig;
    short sAudioData[CVIAUDIO_AEC_LENGTH * CVIAUDIO_CHANNEL] = {0};
    int doDatasize = CVIAUDIO_AEC_LENGTH * sizeof(short);
    int doStep = doDatasize * CVIAUDIO_CHANNEL;

    int doCount = frameSize / CVIAUDIO_AEC_LENGTH;
    for(doIndex = 0;doIndex < doCount;doIndex++)
    {
        doDataIndex = doIndex * doStep;
        #if ENABLE_3A_DATA
        memcpy(audio->datain, &pMicIn[doDataIndex], doStep);
        for (int i = 0; i < CVIAUDIO_AEC_LENGTH; i++) {
            audio->mic_in[i] = audio->datain[i * 2 + MIC_AUDIO_LEFT];
            audio->ref_in[i] = audio->datain[i * 2 + MIC_AUDIO_RIGHT];
        }

        if ((pstVqeConfig->u32OpenMask & AI_TALKVQE_MASK_AEC) == AI_TALKVQE_MASK_AEC) {//aec
            RetframeLen = CviAud_Algo_Process(audio->pssp_handle, audio->mic_in, audio->ref_in, audio->dataout, CVIAUDIO_AEC_LENGTH);
            if (RetframeLen != CVIAUDIO_AEC_LENGTH) {
                JLOG_ERROR("[aec] ssp process fail\n");
                return ;
            }
        } else {
            RetframeLen = CviAud_Algo_Process(audio->pssp_handle, audio->mic_in, NULL, audio->dataout, CVIAUDIO_AEC_LENGTH);
            if (RetframeLen != CVIAUDIO_AEC_LENGTH) {
                JLOG_ERROR("[anr agc] ssp process fail\n");
                return;
            }
        }

        audio_mono2stereo(audio->dataout, CVIAUDIO_AEC_LENGTH, sAudioData);//left short + right short = len*2 short
        #else
        memcpy((char*)&sAudioData[0],(char*)&pMicIn[doDataIndex],doStep);
        #endif
        if(frameDataSize >= doDataIndex + doStep)
        {
            memcpy((char*)&pMicOut[doDataIndex],(char*)&sAudioData[0],doStep);//short = 2*char
        }
    }
}

void audio_capture_set_gain(audio_t *audio, int again, int dgain) {
    csi_codec_input_t *codec = audio->pcm->handle->hdl;
    csi_codec_input_analog_gain(codec, again);
    csi_codec_input_digital_gain(codec, dgain);
}

void audio_play_set_gain(audio_t *audio, int again, int dgain) {
    csi_codec_output_t *codec = audio->pcm->handle->hdl;
    csi_codec_output_analog_gain(codec, again);
    csi_codec_output_digital_gain(codec, dgain);
}