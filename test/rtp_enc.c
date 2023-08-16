#include <aos/kernel.h>
#include "cvi_venc.h"
#include "media_video.h"
// #include "blk_fifo.h"
// #include "RTP_ENC.h"
// #include "rtmp_proc.h"
// #include "cviaudio_algo_interface.h"
// #include "cvi_comm_aio.h"
// #include "rtmp_audio.h"
// #include "cvi_param.h"
// #include <alsa/pcm.h>
#include "rtp.h"
#include "rtp_enc.h"


#define RTP_ENC_INTERVAL 10 //ms

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

int rtp_enc_loop_flag = 0;

static void rtp_enc_entry(void *param) {
    peer_connection_t *pc = param;
    VENC_STREAM_S venc_stream = {0};
    VENC_PACK_S *pPack = NULL;
    int iPackid = 0;
    while (1) {
        // flags = rtmp_event_get(RTMP_EVENT_MASK);
        if (rtp_enc_loop_flag && pc->dtls_srtp.state == DTLS_SRTP_STATE_CONNECTED) {
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
            }
        }
        aos_msleep(1);
    }
}

void rtp_enc_init(peer_connection_t *pc) {
    aos_task_new("rtp_enc", rtp_enc_entry, pc, 30*1024);
}

void rtp_enc_start(peer_connection_t *pc) {
    MEDIA_VIDEO_force_Iframe(0);
    rtp_enc_loop_flag = 1;
}

void rtp_enc_stop(peer_connection_t *pc) {
    rtp_enc_loop_flag = 0;
    aos_msleep(1000);
    peer_connection_reset_video_fifo(pc);
}

void rtp_enc_restart(peer_connection_t *pc) {
    rtp_enc_stop(pc);
    rtp_enc_start(pc);
}

