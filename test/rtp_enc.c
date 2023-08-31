#include <cvi_venc.h>
#include <media_video.h>

#include <media_audio.h>
#include <alsa/pcm.h>
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
#include "thread.h"


#define RTP_VIDEO_ENC_INTERVAL 10 //ms
#define RTP_AUDIO_ENC_INTERVAL 40 //ms

#define PCM_CAPTURE_HW_PARAMS_DIR 1
#define PCM_CAPTURE_HW_PARAMS_FORMAT 16 // 16bit
#define PCM_CAPTURE_HW_PARAMS_FRAME_SIZE (PCM_CAPTURE_HW_PARAMS_FORMAT / 8) // 16bit / 8 = 2bytes
#define PCM_CAPTURE_HW_PARAMS_CHANNEL 1
#define PCM_CAPTURE_HW_PARAMS_RATE 8000
#define PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE 320// 25fps(40ms/packet)
#define PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE (PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * PCM_CAPTURE_HW_PARAMS_CHANNEL * PCM_CAPTURE_HW_PARAMS_FRAME_SIZE)

typedef struct {
    aos_pcm_t *handle;
    int dir;
    unsigned int rate;
    int format;
    int period_size;
    int buffer_size;
    int channel;
} pcm_t;

static pcm_t pcm_capture;
// rtp_pcm_t rtp_pcm_play;

static int pcm_init(pcm_t *pcm, char *name, aos_pcm_stream_t stream) {
    int ret = -1;
    aos_pcm_hw_params_t *hw_params;
    aos_pcm_t *_handle = NULL;
    ret = aos_pcm_open(&pcm->handle, name, stream, 0);
    if (ret < 0) {
        JLOG_ERROR("pcm capture open fail");
        return ret;
    }
    aos_pcm_hw_params_alloca(&hw_params);
    aos_pcm_hw_params_any(pcm->handle, hw_params);

    hw_params->period_size = pcm->period_size;
    hw_params->buffer_size = pcm->buffer_size;

    aos_pcm_hw_params_set_access(pcm->handle, hw_params, AOS_PCM_ACCESS_RW_INTERLEAVED);
    aos_pcm_hw_params_set_format(pcm->handle, hw_params, pcm->format);
    aos_pcm_hw_params_set_rate_near(pcm->handle, hw_params, &pcm->rate, &pcm->dir);
    aos_pcm_hw_params_set_channels(pcm->handle, hw_params, pcm->channel);
    aos_pcm_hw_params(pcm->handle, hw_params);
    //Lango_Set_AudioOutVol(30, 30);
    return 0;
}

static int pcm_capture_init(pcm_t *pcm) {
    int ret = -1;

    //g711-alaw
    pcm16_alaw_tableinit();

    pcm->rate = PCM_CAPTURE_HW_PARAMS_RATE;
    pcm->channel = PCM_CAPTURE_HW_PARAMS_CHANNEL;
    pcm->format = PCM_CAPTURE_HW_PARAMS_FORMAT;
    pcm->dir = PCM_CAPTURE_HW_PARAMS_DIR;
    pcm->period_size = PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE;
    pcm->buffer_size = PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE;

    ret = pcm_init(pcm, "pcmC0", AOS_PCM_STREAM_CAPTURE);

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

static void *rtp_video_enc_thread_entry(void *param) {
    peer_connection_t *pc = param;
    VENC_STREAM_S venc_stream = {0};
    VENC_PACK_S *pPack = NULL;
    int iPackid = 0;

    thread_set_name_self("rtp_video_enc");
    // video initialize
    LG_media_video_init(PARAM_RGB_PIPELINE);

    while (1) {
        // flags = rtmp_event_get(RTMP_EVENT_MASK);
        if (pc->rtp_audio_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            // JLOG_INFO("venc get stream------------------");
            if(MEDIA_VIDEO_VencGetStream(0, &venc_stream, 2000) == CVI_SUCCESS) {
                //parse sps pps
                // JLOG_INFO("venc get stream");
                // venc_process_stream(pc, &venc_stream);

                //pack proc
                for(iPackid = 0; iPackid < venc_stream.u32PackCount; iPackid++ )
                {
                    pPack = &venc_stream.pstPack[iPackid];
                    // peer_connection_send_video(pc, pPack->pu8Addr, pPack->u32Len);
                    rtp_packetizer_encode(&pc->video_packetizer, (uint8_t*)pPack->pu8Addr, pPack->u32Len);
                    //send fifo
                    // while (1) {
                    //     recv_count = packet_fifo_read(&pc->video_fifo, buf, 4096);
                    //     if (recv_count > 0) {
                    //         // JLOG_INFO_DUMP_HEX(buf, recv_count);
                    //         ret = peer_connection_send_rtp_packet(pc, buf, recv_count);
                    //         // JLOG_INFO("send rtp[%d], ret=%d", recv_count, ret);
                    //     } else {
                    //         // no data
                    //         break;
                    //     }
                    // }
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
    pcm_t *pcm = &pcm_capture;
    char pcm_capture_buffer[PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE];
    char pcm_capture_enc_buffer[PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE];

    thread_set_name_self("rtp_audio_enc");
    // audio initialize
    LG_media_audio_init();
    // pcm device init
    pcm_capture_init(pcm);

    while (1) {
        // flags = rtmp_event_get(RTMP_EVENT_MASK);
        if (pc->rtp_audio_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            // memset(pcm_capture_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            // memset(pcm_capture_enc_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            int ret = aos_pcm_readi(pcm->handle, pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            if (ret > 0) {
                int pcm_frame_size = ret * pcm->channel;
                // pcm -> g711-alaw, 16bit to 8bit
                pcm16_to_alaw(pcm_frame_size, pcm_capture_buffer, pcm_capture_enc_buffer);
                rtp_packetizer_encode(&pc->audio_packetizer, (uint8_t*)pcm_capture_enc_buffer, pcm_frame_size);
                // int buffer_size = ret * pcm->channel * (pcm->format / 8);
                // JLOG_INFO_DUMP_HEX(pcm_capture_buffer, buffer_size, "pcm_capture_buffer: read_size=%d, buffer_size=%d", ret, buffer_size);
            }
        }
        usleep(RTP_AUDIO_ENC_INTERVAL*1000);
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
void rtp_enc_init(peer_connection_t *pc) {
    rtp_video_enc_thread_init(pc, rtp_video_enc_thread_entry);
    rtp_audio_enc_thread_init(pc, rtp_audio_enc_thread_entry);
}

void rtp_enc_start(peer_connection_t *pc) {
    MEDIA_VIDEO_force_Iframe(0);
    pc->rtp_video_enc_loop_flag = 1;
    pc->rtp_audio_enc_loop_flag = 1;
}

void rtp_enc_stop(peer_connection_t *pc) {
    pc->rtp_video_enc_loop_flag = 0;
    pc->rtp_audio_enc_loop_flag = 0;
    // usleep(1000*1000);
    // peer_connection_reset_video_fifo(pc);
}

void rtp_enc_restart(peer_connection_t *pc) {
    rtp_enc_stop(pc);
    rtp_enc_start(pc);
}

