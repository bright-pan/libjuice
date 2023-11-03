#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

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
#include "audio_pcm.h"


static pcm_t pcm_capture;
static audio_t audio_capture;

static pcm_t pcm_play;
static audio_t audio_play;


static void rtp_enc_packetizer_callback(char *packet, int bytes, void *user_data) {
    int ret;
    peer_connection_t *pc = user_data;

    // JLOG_INFO("rtp_enc_packetizer_callback [%d:%d]", ntohl(((rtp_header_t *)packet)->ssrc), ntohs(((rtp_header_t *)packet)->seq_number));
    if (((rtp_header_t *)packet)->type == RTP_PAYLOAD_TYPE_H264) {
        ret = rtp_list_insert_packet(&pc->rtp_tx_cache_list, packet, bytes);
        if (ret < 0) {
            JLOG_ERROR("insert rtp_tx_cache_list error, count:%d", rtp_list_count(&pc->rtp_tx_cache_list));
        }
    }
    // send
    if (peer_connection_encrypt_send(pc, packet, bytes) != JUICE_ERR_SUCCESS) {
        JLOG_ERROR("peer_connection_encrypt_send error");
    }
}

static void rtp_enc_rtx_packetizer_callback(char *packet, int bytes, void *user_data) {
    int ret;
    peer_connection_t *pc = user_data;

    ret = rtp_list_insert_packet(&pc->rtp_rtx_cache_list, packet, bytes);
    if (ret < 0) {
        JLOG_ERROR("insert rtp_rtx_cache_list error, count:%d", rtp_list_count(&pc->rtp_rtx_cache_list));
    }
    // JLOG_INFO("rtp_enc_rtx_packetizer_callback [%d:%d]", ntohl(((rtp_header_t *)packet)->ssrc), ntohs(((rtp_header_t *)packet)->seq_number));
    // if (peer_connection_encrypt_send(pc, packet, bytes) != JUICE_ERR_SUCCESS) {
    //     JLOG_ERROR("peer_connection_encrypt_send error");
    // }
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
        if (pc->rtp_video_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            if(MEDIA_VIDEO_VencGetStream(0, &venc_stream, 2000) == CVI_SUCCESS) {
                //pack proc
                for(iPackid = 0; iPackid < venc_stream.u32PackCount; iPackid++ )
                {
                    pPack = &venc_stream.pstPack[iPackid];
                    mutex_lock(&pc->packetizer_mutex);
                    rtp_packetizer_encode(&pc->video_packetizer, (uint8_t*)pPack->pu8Addr, pPack->u32Len);
                    mutex_unlock(&pc->packetizer_mutex);
                }
                // if (venc_stream.u32PackCount > 1)
                //     JLOG_INFO("venc get stream: %d", venc_stream.u32PackCount);
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

void *rtp_audio_enc_thread_entry(void *param) {
    int ret = 0;
    peer_connection_t *pc = param;
    audio_t *capture = &audio_capture;
    pcm_t *pcm = &pcm_capture;
    char pcm_capture_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];
    char pcm_capture_enc_buffer[PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES];

    thread_set_name_self("rtp_audio_enc");
    // audio initialize
    LG_media_audio_init();
    // pcm capture device init

    //pcm16 to g711-alaw
    pcm16_alaw_tableinit();
    audio_capture_init(capture, pcm);

    if (pc->options.audio_codec) {
        uint32_t now_timestamp = aos_now_ms();
        rtp_packetizer_init(&pc->audio_packetizer, pc->options.audio_codec,
                            now_timestamp, rtp_enc_packetizer_callback, pc);
    }

    // audio demo init
    // audio_demo_init(AUDIO_DEMO_LENGTH, AUDIO_DEMO_CHANNEL_NUM, AUDIO_DEMO_BIT_DEPTH);

    while (1) {
        // flags = rtmp_event_get(RTMP_EVENT_MASK);
        if (pc->rtp_audio_enc_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            // memset(pcm_capture_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            // memset(pcm_capture_enc_buffer, 0, PCM_CAPTURE_HW_PARAMS_BUFFER_SIZE);
            ret = aos_pcm_readi(capture->pcm->handle, pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            // ret = audio_demo_readi((unsigned char *)pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
            if (ret > 0) {
                // CVI 3a process
                audio_3a_process(capture, pcm_capture_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_BYTES);
                audio_stereo2mono((short *)pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE, (short *)pcm_capture_buffer, MIC_AUDIO_LEFT);
                // pcm -> g711-alaw, 16bit to 8bit, mono channel
                pcm16_to_alaw(PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE * PCM_CAPTURE_HW_PARAMS_BIT_DEPTH_BYTES, pcm_capture_buffer, pcm_capture_enc_buffer);
                mutex_lock(&pc->packetizer_mutex);
                rtp_packetizer_encode(&pc->audio_packetizer, (uint8_t*)pcm_capture_enc_buffer, PCM_CAPTURE_HW_PARAMS_PERIOD_SIZE);
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
void *rtp_audio_dec_thread_entry(void *param) {
    int ret = 0;
    rtp_frame_t *frame;
    rtp_frame_t *tmp;
    peer_connection_t *pc = param;
    audio_t *play = &audio_play;
    pcm_t *pcm = &pcm_play;
    rtp_packet_t *rtp_packet;
    int rtp_payload_len = 0;
    int pcm_play_period_size = 0; // play window size
    char pcm_play_buffer[PCM_PLAY_HW_PARAMS_PERIOD_BYTES];

    thread_set_name_self("rtp_audio_dec");
    // audio initialize
    LG_media_audio_init();
    // pcm device init
    audio_play_init(play, pcm);

    // audio demo init
    //audio_demo_init(AUDIO_DEMO_LENGTH, AUDIO_DEMO_CHANNEL_NUM, AUDIO_DEMO_BIT_DEPTH);

    while (1) {
        if (pc->rtp_audio_dec_loop_flag && pc->state == PEER_CONNECTION_COMPLETED) {
            if (rtp_list_count(&pc->rtp_recv_cache_list) > 0) {
                HASH_ITER(hh, pc->rtp_recv_cache_list.utlist, frame, tmp) {
                    // process rtp packet
                    rtp_packet = (rtp_packet_t *)frame->packet;
                    if (rtp_packet->header.type == RTP_PAYLOAD_TYPE_PCMA) {
                        rtp_payload_len = frame->bytes - sizeof(rtp_packet_t);
                        if (rtp_payload_len > PCM_PLAY_HW_PARAMS_PERIOD_SIZE - pcm_play_period_size) {
                            // decode length is not overflow for pcm_play_buffer
                            rtp_payload_len = PCM_PLAY_HW_PARAMS_PERIOD_SIZE - pcm_play_period_size;
                        }
                        // decode g711a to pcm16
                        alaw_to_pcm16(rtp_payload_len, (char *)rtp_packet->payload, pcm_play_buffer + pcm_play_period_size * 2);
                        if (pcm_play_period_size + rtp_payload_len >= PCM_PLAY_HW_PARAMS_PERIOD_SIZE) {
                            ret = aos_pcm_writei(play->pcm->handle, pcm_play_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
                            aos_pcm_write_wait_complete(play->pcm->handle, PCM_PLAY_PERIOD_TIMEOUT);
                            if(ret < 0) {
                                JLOG_ERROR("pcm play error: ret=%d", ret);
                            } else {
                                // JLOG_INFO("pcm play: period_size=%d", pcm_play_period_size);
                                //LANGO_LOG_INFO("play audio: %d, dstlen:%d, %d", nReadSize, dstlen,
                                //               aos_pcm_bytes_to_frames(rtmp_audio.play_handle, dstlen));
                            }
                            pcm_play_period_size = 0; // reset
                        } else {
                            pcm_play_period_size += rtp_payload_len;
                            // JLOG_INFO("pcm play: period_size!=%d", PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
                        }
                    } else {
                        JLOG_ERROR("rtp_audio_dec payload type is not PCMA/G711A, type:%d, length:%d", rtp_packet->header.type, rtp_payload_len);
                    }
                    // remove frame
                    rtp_list_delete(&pc->rtp_recv_cache_list, frame);
                }
            } else {
                usleep(5*1000);
            }
        }
        /*
        if (pc->rtp_audio_dec_loop_flag) {
            ret = audio_demo_readi((unsigned char *)pcm_capture_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
            if (ret > 0) {
                audio_stereo2mono(play, (short *)pcm_play_buffer, (short *)pcm_play_process_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE, MIC_AUDIO_LEFT);
                ret = aos_pcm_writei(play->pcm->handle, pcm_play_process_buffer, PCM_PLAY_HW_PARAMS_PERIOD_SIZE);
                aos_pcm_write_wait_complete(play->pcm->handle, 100);
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

//audio dec
void rtp_audio_dec_init(peer_connection_t *pc) {
    rtp_audio_dec_thread_init(pc, rtp_audio_dec_thread_entry);
}

void rtp_audio_dec_start(peer_connection_t *pc) {
    pc->rtp_audio_dec_loop_flag = 1;
}

void rtp_audio_dec_stop(peer_connection_t *pc) {
    pc->rtp_audio_dec_loop_flag = 0;
}

void rtp_audio_dec_restart(peer_connection_t *pc) {
    rtp_audio_dec_stop(pc);
    rtp_audio_dec_start(pc);
}

// dec
void rtp_dec_init(peer_connection_t *pc) {
    rtp_audio_dec_init(pc);
}

void rtp_dec_start(peer_connection_t *pc) {
    rtp_audio_dec_start(pc);
}

void rtp_dec_stop(peer_connection_t *pc) {
    rtp_audio_dec_stop(pc);
}

void rtp_dec_restart(peer_connection_t *pc) {
    rtp_audio_dec_restart(pc);
}

//video enc
void rtp_video_enc_init(peer_connection_t *pc) {
    rtp_video_enc_thread_init(pc, rtp_video_enc_thread_entry);
}

void rtp_video_enc_start(peer_connection_t *pc) {
    MEDIA_VIDEO_force_Iframe(0);
    pc->rtp_video_enc_loop_flag = 1;
}

void rtp_video_enc_stop(peer_connection_t *pc) {
    pc->rtp_video_enc_loop_flag = 0;
}

void rtp_video_enc_restart(peer_connection_t *pc) {
    rtp_video_enc_stop(pc);
    rtp_video_enc_start(pc);
}

// audio enc
void rtp_audio_enc_init(peer_connection_t *pc) {
    rtp_audio_enc_thread_init(pc, rtp_audio_enc_thread_entry);
}

void rtp_audio_enc_start(peer_connection_t *pc) {
    pc->rtp_audio_enc_loop_flag = 1;
}

void rtp_audio_enc_stop(peer_connection_t *pc) {
    pc->rtp_audio_enc_loop_flag = 0;
}

void rtp_audio_enc_restart(peer_connection_t *pc) {
    rtp_audio_enc_stop(pc);
    rtp_audio_enc_start(pc);
}

// enc
void rtp_enc_init(peer_connection_t *pc) {
    rtp_video_enc_init(pc);
    rtp_audio_enc_init(pc);
}

void rtp_enc_start(peer_connection_t *pc) {
    rtp_video_enc_start(pc);
    rtp_audio_enc_start(pc);
}

void rtp_enc_stop(peer_connection_t *pc) {
    rtp_video_enc_stop(pc);
    rtp_audio_enc_stop(pc);
}

void rtp_enc_restart(peer_connection_t *pc) {
    rtp_video_enc_restart(pc);
    rtp_audio_enc_restart(pc);
}
