#include <cvi_venc.h>
#include <media_video.h>

#include <media_audio.h>
#include <alsa/pcm.h>
#include <cviaudio_algo_interface.h>
#include <cvi_comm_aio.h>
#include <g711.h>
#include <g711_table.h>

#include <lango_default_define.h>
// #include "blk_fifo.h"
// #include "RTP_ENC.h"
// #include "rtmp_proc.h"
// #include "cviaudio_algo_interface.h"
// #include "cvi_comm_aio.h"
// #include "rtmp_audio.h"
// #include "cvi_param.h"
#include "rtp.h"
#include "rtp_enc.h"
#include "peer_connection.h"
#include "thread.h"
#include "audio_demo.h"


#define ENABLE_3A_DATA 1

#define MIC_AUDIO_LEFT 0
#define MIC_AUDIO_RIGHT 1

#define RTP_VIDEO_ENC_INTERVAL 10 //ms
#define RTP_AUDIO_ENC_INTERVAL 20 //ms

#define PCM_CAPTURE_DEVICE_NAME "pcmC0"
#define PCM_CAPTURE_DEVICE_STREAM AOS_PCM_STREAM_CAPTURE

#define PCM_CAPTURE_HW_PARAMS_DIR 1
#define PCM_CAPTURE_HW_PARAMS_BIT_DEPTH 16 // sample depth
#define PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES (PCM_CAPTURE_HW_PARAMS_BIT_DEPTH / 8) // sample depth bytes
#define PCM_CAPTURE_HW_PARAMS_CHANNEL 2 // sample channel
#define PCM_CAPTURE_HW_PARAMS_RATE 8000 // sample rate
#define PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE 320// 25fps(40ms/packet) sample window size
#define PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES (PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES * PCM_CAPTURE_HW_PARAMS_CHANNEL)
#define PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE (PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * 2) // sample window buffer size
#define PCM_CAPTURE_HW_PARAMS_BUFFER_BYTES (PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES * PCM_CAPTURE_HW_PARAMS_CHANNEL)

#define CVIAUDIO_CHANNEL PCM_CAPTURE_HW_PARAMS_CHANNEL
#define CVIAUDIO_PER_SAMPLE PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES
#define CVIAUDIO_AEC_LENGTH 160


#define PCM_PLAY_DEVICE_NAME "pcmP0"
#define PCM_PLAY_DEVICE_STREAM AOS_PCM_STREAM_PLAYBACK

#define RTP_AUDIO_DEC_PERIOD_SIZE 160

#define PCM_PLAY_HW_PARAMS_DIR 0
#define PCM_PLAY_HW_PARAMS_BIT_DEPTH 16 // play depth
#define PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES (PCM_PLAY_HW_PARAMS_BIT_DEPTH / 8) // play depth bytes
#define PCM_PLAY_HW_PARAMS_CHANNEL 1
#define PCM_PLAY_HW_PARAMS_RATE 8000
#define PCM_PLAY_HW_PARAMS_PERIOD_SIZE 1280 // 10fps(100ms/packet) play window size
#define PCM_PLAY_HW_PARAMS_PERIOD_BYTES (PCM_PLAY_HW_PARAMS_PERIOD_SIZE * PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES * PCM_PLAY_HW_PARAMS_CHANNEL)
#define PCM_PLAY_HW_PARAMS_BUFFER_SIZE (PCM_PLAY_HW_PARAMS_PERIOD_SIZE * 2) // play window buuffer size
#define PCM_PLAY_HW_PARAMS_BUFFER_BYTES (PCM_PLAY_HW_PARAMS_BUFFER_SIZE * PCM_PLAY_HW_PARAMS_BIT_DEPTH_BYTES * PCM_PLAY_HW_PARAMS_CHANNEL)

#define RTP_AUDIO_DEC_PERIOD_PACKET_SIZE (PCM_PLAY_HW_PARAMS_PERIOD_SIZE / RTP_AUDIO_DEC_PERIOD_SIZE)

#define RTP_AUDIO_DEC_INTERVAL (RTP_AUDIO_DEC_PERIOD_SIZE * 1000 / PCM_PLAY_HW_PARAMS_RATE) //20ms

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

static pcm_t pcm_capture;
static audio_t audio_capture;

static pcm_t pcm_play;
static audio_t audio_play;

static int pcm_init(pcm_t *pcm, char *name, aos_pcm_stream_t stream) {
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

static int pcm_capture_init(pcm_t *pcm) {
    int ret = -1;

    //pcm16 to g711-alaw
    pcm16_alaw_tableinit();

    pcm->rate = PCM_CAPTURE_HW_PARAMS_RATE;
    pcm->channel = PCM_CAPTURE_HW_PARAMS_CHANNEL;
    pcm->bit_depth = PCM_CAPTURE_HW_PARAMS_BIT_DEPTH;
    pcm->dir = PCM_CAPTURE_HW_PARAMS_DIR;
    pcm->period_size = PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE;
    pcm->buffer_size = PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE;

    ret = pcm_init(pcm, PCM_CAPTURE_DEVICE_NAME, PCM_CAPTURE_DEVICE_STREAM);

    return ret;
}

static int pcm_play_init(pcm_t *pcm) {
    int ret = -1;

    //g711-alaw to pcm16
    alaw_pcm16_tableinit();

    pcm->rate = PCM_PLAY_HW_PARAMS_RATE;
    pcm->channel = PCM_PLAY_HW_PARAMS_CHANNEL;
    pcm->bit_depth = PCM_PLAY_HW_PARAMS_BIT_DEPTH;
    pcm->dir = PCM_PLAY_HW_PARAMS_DIR;
    pcm->period_size = PCM_PLAY_HW_PARAMS_PERIOD_SIZE;
    pcm->buffer_size = PCM_PLAY_HW_PARAMS_BUFFER_SIZE;

    ret = pcm_init(pcm, PCM_PLAY_DEVICE_NAME, PCM_PLAY_DEVICE_STREAM);

    return ret;
}

// //start code is 4 or 3 byte
// static int get_startcode_size(unsigned char * pData)
// {
//     int index = 0, nSize = 0;
//     for(index = 0; index < 4; index++) {
//         if(pData[index] == 0x00) {
//             nSize++;
//         } else if (pData[index] == 0x01) {
//             nSize = (nSize < 2) ? 0 : nSize + 1 ;
//             break;
//         } else {
//             nSize = 0;
//             break;
//         }
//     }
//     return nSize;
// }
        /*
static int venc_process_stream(peer_connection_t *pc, VENC_STREAM_S *pstream)
{
    VENC_PACK_S *pPack = NULL;
    int iPackid = 0;
    int nStartCodeSize;

    //pack proc
    for(iPackid = 0; iPackid < pstream->u32PackCount; iPackid++ )
    {
        pPack = &pstream->pstPack[iPackid];
        peer_connection_send_video(pc, pPack->pu8Addr, pPack->u32Len);
        //get start code
        // nStartCodeSize = get_startcode_size(pPack->pu8Addr);
        // if(nStartCodeSize == 0) {
        //     JLOG_ERROR("!!!!! read stream fail !!!!!");
        //     continue;
        // }
        // //H264
        // H264E_NALU_TYPE_E NaluType = pPack->DataType.enH264EType;
        // if(NaluType == H264E_NALU_SPS) {
        //     JLOG_INFO("h264 Sps: %d, %d", iPackid, pPack->u32Len - nStartCodeSize);
        // } else if(NaluType == H264E_NALU_PPS) {
        //     JLOG_INFO("h264 Pps: %d, %d", iPackid, pPack->u32Len - nStartCodeSize);
        // } else if (NaluType == H264E_NALU_IDRSLICE) {
        //     // pframe->data = &pPack->pu8Addr[nStartCodeSize];
        //     JLOG_INFO("h264 %-3s: %d, %d", "I", iPackid, pPack->u32Len - nStartCodeSize);
        // } else {
        //     JLOG_INFO("h264 %-3s: %d, %d", "P", iPackid, pPack->u32Len - nStartCodeSize);
        // }

        //get start code
        nStartCodeSize = get_startcode_size(pPack->pu8Addr);
        if(nStartCodeSize == 0) {
            LANGO_LOG_ERR("!!!!! read stream fail !!!!!");
            continue;
        }
        if(flags & RTMP_EVENT_VENC_H265) {
            H265E_NALU_TYPE_E H265NaluType = pPack->DataType.enH265EType;
            //LG_LOG_INFO("HHHH265 Type %d", H265NaluType);
            //H265 fix it
            if(H265NaluType == H265E_NALU_SPS)
            {
                rtmp_meta.nSpsLen = pPack->u32Len - nStartCodeSize;
                memcpy(rtmp_meta.Sps,&pPack->pu8Addr[nStartCodeSize], rtmp_meta.nSpsLen);
                //LANGO_LOG_INFO("h265 Sps: %d, %d", iPackid, rtmp_meta.nSpsLen);
            }
            else if(H265NaluType == H265E_NALU_PPS)
            {
                rtmp_meta.nPpsLen = pPack->u32Len - nStartCodeSize;
                memcpy(rtmp_meta.Pps, &pPack->pu8Addr[nStartCodeSize], rtmp_meta.nPpsLen);
                //LANGO_LOG_INFO("h265 Pps: %d, %d", iPackid, rtmp_meta.nPpsLen);
            }
            else if(H265NaluType == H265E_NALU_VPS)
            {
                //fix it
                rtmp_meta.nVpsLen = pPack->u32Len - nStartCodeSize;
                memcpy(rtmp_meta.Vps, &pPack->pu8Addr[nStartCodeSize], rtmp_meta.nVpsLen);
                //LANGO_LOG_INFO("h265 Vps: %d, %d", iPackid, rtmp_meta.nVpsLen);
            }
            else
            {
                pframe->code = RTMP_FRAME_CODE_H265;
                pframe->data_size = pPack->u32Len - nStartCodeSize;
                pframe->data = &pPack->pu8Addr[nStartCodeSize];
                if (H265NaluType == H265E_NALU_IDRSLICE || H265NaluType == H265E_NALU_ISLICE) {
                    pframe->type = RTMP_FRAME_TYPE_I;
                    //LANGO_LOG_INFO("h265 %-3s: %d, %d", "I", iPackid, pframe->data_size);
                } else {
                    pframe->type = RTMP_FRAME_TYPE_P;
                    //LANGO_LOG_INFO("h265 %-3s: %d, %d", "P", iPackid, pframe->data_size);
                }


            }
        } else {
            //H264
            H264E_NALU_TYPE_E NaluType = pPack->DataType.enH264EType;
            if(NaluType == H264E_NALU_SPS)
            {
                rtmp_meta.nSpsLen = pPack->u32Len - nStartCodeSize;
                memcpy(rtmp_meta.Sps,&pPack->pu8Addr[nStartCodeSize], rtmp_meta.nSpsLen);
                LANGO_LOG_INFO("h264 Sps: %d, %d", iPackid, rtmp_meta.nSpsLen);
            }
            else if(NaluType == H264E_NALU_PPS)
            {
                rtmp_meta.nPpsLen = pPack->u32Len - nStartCodeSize;
                memcpy(rtmp_meta.Pps, &pPack->pu8Addr[nStartCodeSize], rtmp_meta.nPpsLen);
                LANGO_LOG_INFO("h264 Pps: %d, %d", iPackid, rtmp_meta.nPpsLen);
            }
            else
            {
                pframe->code = RTMP_FRAME_CODE_H264;
                pframe->data_size = pPack->u32Len - nStartCodeSize;
                pframe->data = &pPack->pu8Addr[nStartCodeSize];
                if (NaluType == H264E_NALU_IDRSLICE) {
                    pframe->type = RTMP_FRAME_TYPE_I;
                    LANGO_LOG_INFO("h264 %-3s: %d, %d", "I", iPackid, pframe->data_size);
                } else {
                    pframe->type = RTMP_FRAME_TYPE_P;
                    //LANGO_LOG_INFO("h264 %-3s: %d, %d", "P", iPackid, pframe->data_size);
                }
            }
        }
        //send data
        if(pframe->data != NULL)
        {
            void *p;
            pframe->seq = seq++;
            pframe->tus = pstream->pstPack->u64PTS/1000;
            if (rtmp_fifo_write(pframe, pframe->data) < 0) {
                mempool_trace();
                LANGO_LOG_ERR("rtmp fifo venc write failure!");
            }
        }
    }
    return 0;
}*/

// void video_frame_loss(int s32_loss_num) {
//     VENC_STREAM_S venc_stream = {0};
//     while(s32_loss_num-- > 0) {
//         if(MEDIA_VIDEO_VencGetStream(0, &venc_stream, 2000) == CVI_SUCCESS) {
//             MEDIA_VIDEO_VencReleaseStream(0, &venc_stream);
//         }
//     }
// }

static void audio_3a_init(audio_t *audio)
{
    char pstrVersion[52];
    int channel = audio->pcm->channel;/* only support 2chn*/
    int capture_rate = audio->pcm->rate;
    int AecLenByte = 0;

    AI_TALKVQE_CONFIG_S *pstVqeConfig = &audio->stVqeConfig;

    pstVqeConfig->para_client_config = 0;
    pstVqeConfig->u32OpenMask = AI_TALKVQE_MASK_AEC | AI_TALKVQE_MASK_AGC | AI_TALKVQE_MASK_ANR;//
    pstVqeConfig->s32WorkSampleRate = capture_rate;
    pstVqeConfig->s32RevMask = 0;
    pstVqeConfig->para_notch_freq = 0;
    /* AEC */
    pstVqeConfig->stAecCfg.para_aec_filter_len = 13;
    pstVqeConfig->stAecCfg.para_aes_std_thrd = 37;
    pstVqeConfig->stAecCfg.para_aes_supp_coeff = 60;
    /* ANR */
    pstVqeConfig->stAnrCfg.para_nr_snr_coeff = 15;
    pstVqeConfig->stAnrCfg.para_nr_init_sile_time = 0;

    /* AGC */
    pstVqeConfig->stAgcCfg.para_agc_max_gain = 3;
    pstVqeConfig->stAgcCfg.para_agc_target_high = 2;
    pstVqeConfig->stAgcCfg.para_agc_target_low = 6;
    pstVqeConfig->stAgcCfg.para_agc_vad_ena = 0;

    pstVqeConfig->stAecDelayCfg.para_aec_init_filter_len = 2;
    pstVqeConfig->stAecDelayCfg.para_dg_target = 1;
    pstVqeConfig->stAecDelayCfg.para_delay_sample = 1;

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

static void audio_capture_init(audio_t *audio) {
    pcm_capture_init(&pcm_capture);
    audio->pcm = &pcm_capture;
    audio_3a_init(audio);
}

extern int Lango_Set_AudioOutVol(int again, int dgain);
static void audio_play_init(audio_t *audio) {
    pcm_play_init(&pcm_play);
    audio->pcm = &pcm_play;
    Lango_Set_AudioOutVol(30, 30);
}

static int audio_mono2stereo(audio_t *audio, const short *src_audio, short *dst_audio, int size)
{
    for (int i = 0; i < size; i++)
    {
        for (int channel_num = 0; channel_num < audio->pcm->channel; channel_num++)
            dst_audio[audio->pcm->channel * i + channel_num] = src_audio[i];
    }
    return size;
}

static int audio_stereo2mono(audio_t *audio, const short *src_audio, short *dst_audio, int size, int channel_num)
{
    for (int i = 0; i < size; i++)
    {
        dst_audio[i] = src_audio[i * audio->pcm->channel + channel_num];
    }
    return size;
}

static void audio_3a_process(audio_t *audio, char *pMicIn,int frameSize ,char *pMicOut,int frameDataSize)
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

        audio_mono2stereo(audio, audio->dataout, sAudioData, CVIAUDIO_AEC_LENGTH);//left short + right short = len*2 short
        #else
        memcpy((char*)&sAudioData[0],(char*)&pMicIn[doDataIndex],doStep);
        #endif
        if(frameDataSize >= doDataIndex + doStep)
        {
            memcpy((char*)&pMicOut[doDataIndex],(char*)&sAudioData[0],doStep);//short = 2*char
        }
    }
}

static void rtp_enc_packetizer_callback(char *packet, int bytes, void *user_data) {
    int ret;
    peer_connection_t *pc = user_data;

    // JLOG_INFO("rtp_enc_packetizer_callback [%d:%d]", ntohl(((rtp_header_t *)packet)->ssrc), ntohs(((rtp_header_t *)packet)->seq_number));
    if (((rtp_header_t *)packet)->type == RTP_PAYLOAD_TYPE_H264) {
        ret = rtp_list_insert_packet(&pc->rtp_tx_cache_list, packet, bytes);
        if (ret < 0) {
            JLOG_ERROR("rtp_list_insert_packet error, count:%d", rtp_list_count(&pc->rtp_tx_cache_list));
        }
    }
    // send
    if (peer_connection_encrypt_send(pc, packet, bytes) != JUICE_ERR_SUCCESS) {
        JLOG_ERROR("peer_connection_encrypt_send error");
    }
}

static void rtp_enc_rtx_packetizer_callback(char *packet, int bytes, void *user_data) {
    peer_connection_t *pc = user_data;

    // JLOG_INFO("rtp_enc_rtx_packetizer_callback [%d:%d]", ntohl(((rtp_header_t *)packet)->ssrc), ntohs(((rtp_header_t *)packet)->seq_number));
    if (peer_connection_encrypt_send(pc, packet, bytes) != JUICE_ERR_SUCCESS) {
        JLOG_ERROR("peer_connection_encrypt_send error");
    }
}

static void *rtp_video_enc_thread_entry(void *param) {
    peer_connection_t *pc = param;
    VENC_STREAM_S venc_stream = {0};
    VENC_PACK_S *pPack = NULL;
    int iPackid = 0;

    thread_set_name_self("rtp_video_enc");
    // video initialize
    LG_media_video_init(PARAM_RGB_PIPELINE);

    uint32_t now_timestamp = current_timestamp();
    if (pc->options.video_codec) {
        rtp_packetizer_init(&pc->video_packetizer, pc->options.video_codec,
                            now_timestamp, rtp_enc_packetizer_callback, pc);
    }

    if (pc->options.video_rtx_codec) {
        rtp_packetizer_init(&pc->video_rtx_packetizer, pc->options.video_rtx_codec,
                            now_timestamp, rtp_enc_rtx_packetizer_callback, pc);
    }

    while (1) {
        if (pc->rtp_audio_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            if(MEDIA_VIDEO_VencGetStream(0, &venc_stream, 2000) == CVI_SUCCESS) {
                //pack proc
                for(iPackid = 0; iPackid < venc_stream.u32PackCount; iPackid++ )
                {
                    pPack = &venc_stream.pstPack[iPackid];
                    mutex_lock(&pc->packetizer_mutex);
                    rtp_packetizer_encode(&pc->video_packetizer, (uint8_t*)pPack->pu8Addr, pPack->u32Len);
                    mutex_unlock(&pc->packetizer_mutex);
                }
                MEDIA_VIDEO_VencReleaseStream(0, &venc_stream);
            } else {
                usleep(1000*RTP_VIDEO_ENC_INTERVAL);
            }
        } else {
            usleep(RTP_VIDEO_ENC_INTERVAL*1000);
        }
    }
    pthread_exit(&pc->rtp_video_enc_loop_flag);
    return NULL;
}

static void *rtp_audio_enc_thread_entry(void *param) {
    peer_connection_t *pc = param;
    audio_t *audio = &audio_capture;
    char pcm_capture_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];
    char pcm_capture_enc_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];

    thread_set_name_self("rtp_audio_enc");
    // audio initialize
    LG_media_audio_init();
    // pcm capture device init
    audio_capture_init(audio);

    if (pc->options.audio_codec) {
        uint32_t now_timestamp = aos_now_ms();
        rtp_packetizer_init(&pc->audio_packetizer, pc->options.audio_codec,
                            now_timestamp, rtp_enc_packetizer_callback, pc);
    }

    while (1) {
        // flags = rtmp_event_get(RTMP_EVENT_MASK);
        if (pc->rtp_audio_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            // memset(pcm_capture_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            // memset(pcm_capture_enc_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            int ret = aos_pcm_readi(audio->pcm->handle, pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            // int ret = pcm_read_demo((unsigned char *)pcm_capture_buffer, __2_pcm);
            if (ret > 0) {
                // CVI 3a process
                audio_3a_process(audio, pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
                audio_stereo2mono(audio, (short *)pcm_capture_buffer, (short *)pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, MIC_AUDIO_LEFT);
                // pcm -> g711-alaw, 16bit to 8bit, mono channel
                pcm16_to_alaw(PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES, pcm_capture_enc_buffer, pcm_capture_buffer);
                mutex_lock(&pc->packetizer_mutex);
                rtp_packetizer_encode(&pc->audio_packetizer, (uint8_t*)pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
                mutex_unlock(&pc->packetizer_mutex);
                // int buffer_size = ret * pcm->channel * (pcm->bit_depth / 8);
                // JLOG_INFO_DUMP_HEX(pcm_capture_buffer, buffer_size, "pcm_capture_buffer: read_size=%d, buffer_size=%d", ret, buffer_size);
            } else {
                usleep(RTP_AUDIO_ENC_INTERVAL*1000);
            }
        }
        usleep(RTP_AUDIO_ENC_INTERVAL*1000);
    }
    pthread_exit(&pc->rtp_audio_enc_loop_flag);
    return NULL;
}

extern int aos_pcm_write_wait_complete(aos_pcm_t *pcm, int timeout);
static void *rtp_audio_dec_thread_entry(void *param) {
    int ret = 0;
    rtp_frame_t *frame;
    rtp_frame_t *tmp;
    peer_connection_t *pc = param;
    audio_t *audio = &audio_play;
    rtp_packet_t *rtp_packet;
    int rtp_payload_len = 0;
    int pcm_play_period_size = 0; // play window size
    char pcm_play_buffer[PCM_PLAY_HW_PARAMS_PERIOD_BYTES];

    thread_set_name_self("rtp_audio_dec");
    // audio initialize
    LG_media_audio_init();
    // pcm device init
    audio_play_init(audio);

    while (1) {
        if (pc->rtp_audio_dec_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            if (rtp_list_count(&pc->rtp_recv_cache_list) > 0) {
                HASH_ITER(hh, pc->rtp_recv_cache_list.utlist, frame, tmp) {
                    // process rtp packet
                    rtp_packet = (rtp_packet_t *)frame->packet;
                    if (rtp_packet->header.type == RTP_PAYLOAD_TYPE_PCMA) {
                        rtp_payload_len = frame->bytes - sizeof(rtp_packet_t);
                        // decode g711a to pcm16
                        alaw_to_pcm16(rtp_payload_len, (char *)rtp_packet->payload, pcm_play_buffer + pcm_play_period_size * 2);
                        if (pcm_play_period_size + rtp_payload_len >= PCM_PLAY_HW_PARAMS_PERIOD_SIZE) {
                            pcm_play_period_size = 0;
                            ret = aos_pcm_writei(audio->pcm->handle, pcm_play_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
                            aos_pcm_write_wait_complete(audio->pcm->handle, 100);
                            if(ret < 0) {
                                JLOG_ERROR("pcm_write error: ");
                            } else {
                                //LANGO_LOG_INFO("play audio: %d, dstlen:%d, %d", nReadSize, dstlen,
                                //               aos_pcm_bytes_to_frames(rtmp_audio.play_handle, dstlen));
                            }
                        } else {
                            pcm_play_period_size += rtp_payload_len;
                        }
                    } else {
                        JLOG_ERROR("rtp_audio_dec payload type is not PCMA/G711A, type:%d, length:%d", rtp_packet->header.type, rtp_payload_len);
                    }
                    // remove frame
                    rtp_list_delete(&pc->rtp_recv_cache_list, frame);
                }
            } else {
                usleep(RTP_AUDIO_DEC_INTERVAL*1000);
            }
        }
        /*
        if (pc->rtp_audio_dec_loop_flag) {
            ret = audio_demo_readi((unsigned char *)pcm_play_buffer);
            if (ret > 0) {
                audio_stereo2mono(audio, (short *)pcm_play_buffer, (short *)pcm_play_process_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE, MIC_AUDIO_LEFT);
                ret = aos_pcm_writei(audio->pcm->handle, pcm_play_process_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
                aos_pcm_write_wait_complete(audio->pcm->handle, 100);
                if(ret < 0){
                    JLOG_ERROR("write error");
                } else {
                    //LANGO_LOG_INFO("play audio: %d, dstlen:%d, %d", nReadSize, dstlen,
                    //               aos_pcm_bytes_to_frames(rtmp_audio.play_handle, dstlen));
                }
            }
            // usleep(RTP_AUDIO_DEC_INTERVAL*1000);
        }
        */
        usleep(RTP_AUDIO_DEC_INTERVAL*1000);
    }
    pthread_exit(&pc->rtp_audio_enc_loop_flag);
    return NULL;
}

int rtp_video_enc_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->rtp_video_enc_thread == NULL) {
        thread_attr_init(&attr, pc->rtp_video_enc_thread_prio, pc->rtp_video_enc_thread_ssize);
        ret = thread_init_ex(&pc->rtp_video_enc_thread, &attr, thread_entry, pc);
        if (ret != 0) {
            JLOG_ERROR("rtp_video_enc thread created failure!");
        } else {
            JLOG_INFO("rtp_video_enc thread created!");
        }
    } else {
        JLOG_ERROR("rtp_video_enc thread has beed created!");
    }
    return ret;
}

int rtp_audio_enc_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->rtp_audio_enc_thread == NULL) {
        thread_attr_init(&attr, pc->rtp_audio_enc_thread_prio, pc->rtp_audio_enc_thread_ssize);
        ret = thread_init_ex(&pc->rtp_audio_enc_thread, &attr, thread_entry, pc);
        if (ret != 0) {
            JLOG_ERROR("rtp_audio_enc thread created failure!");
        } else {
            JLOG_INFO("rtp_audio_enc thread created!");
        }
    } else {
        JLOG_ERROR("rtp_audio_enc thread has beed created!");
    }
    return ret;
}

int rtp_audio_dec_thread_init(peer_connection_t *pc, void *(*thread_entry)(void *)) {
    int ret = -1;
    thread_attr_t attr;

    if (pc->rtp_audio_dec_thread == NULL) {
        thread_attr_init(&attr, pc->rtp_audio_dec_thread_prio, pc->rtp_audio_dec_thread_ssize);
        ret = thread_init_ex(&pc->rtp_audio_dec_thread, &attr, thread_entry, pc);
        if (ret != 0) {
            JLOG_ERROR("rtp_audio_dec thread created failure!");
        } else {
            JLOG_INFO("rtp_audio_dec thread created!");
        }
    } else {
        JLOG_ERROR("rtp_audio_dec thread has beed created!");
    }
    return ret;
}

void rtp_enc_init(peer_connection_t *pc) {
    rtp_video_enc_thread_init(pc, rtp_video_enc_thread_entry);
    rtp_audio_enc_thread_init(pc, rtp_audio_enc_thread_entry);
}

void rtp_dec_init(peer_connection_t *pc) {
    rtp_audio_dec_thread_init(pc, rtp_audio_dec_thread_entry);
}

int rtcp_psfb_pli_process(void) {
    int ret = -1;
    static timestamp_t old = 0;

    timestamp_t now = current_timestamp();
    if (now - old >= RTCP_PSFB_PLI_PROCESS_INTERVAL) {
        old = now;
        MEDIA_VIDEO_force_Iframe(0);
        ret = 0;
    }

    return ret;
}

void rtp_enc_start(peer_connection_t *pc) {
    MEDIA_VIDEO_force_Iframe(0);
    pc->rtp_video_enc_loop_flag = 1;
    pc->rtp_audio_enc_loop_flag = 1;
}

void rtp_dec_start(peer_connection_t *pc) {
    pc->rtp_audio_dec_loop_flag = 1;
}

void rtp_enc_stop(peer_connection_t *pc) {
    pc->rtp_video_enc_loop_flag = 0;
    pc->rtp_audio_enc_loop_flag = 0;
    // usleep(1000*1000);
    // peer_connection_reset_video_fifo(pc);
}

void rtp_dec_stop(peer_connection_t *pc) {
    pc->rtp_audio_dec_loop_flag = 0;
    // usleep(1000*1000);
    // peer_connection_reset_video_fifo(pc);
}

void rtp_enc_restart(peer_connection_t *pc) {
    rtp_enc_stop(pc);
    rtp_enc_start(pc);
}

void rtp_dec_restart(peer_connection_t *pc) {
    rtp_dec_stop(pc);
    rtp_dec_start(pc);
}

