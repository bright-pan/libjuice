
#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <aos/kernel.h>
#include <cJSON.h>

#include "paho_mqtt.h"
#include "juice/juice.h"
#include "peer_connection.h"
#include "sdp.h"
#include "udp.h"
#include "utils.h"
#include "log.h"


/**
 * MQTT URI farmat:
 * domain mode
 * tcp://iot.eclipse.org:1883
 *
 * ipv4 mode
 * tcp://192.168.10.1:1883
 * ssl://192.168.10.1:1884
 *
 * ipv6 mode
 * tcp://[fe80::20c:29ff:fe9a:a07e]:1883
 * ssl://[fe80::20c:29ff:fe9a:a07e]:1884
 */

/* define MQTT client context */
static MQTTClient client;
static int is_started = 0;
static char cmd_buf[SDP_CONTENT_LENGTH];


extern peer_connection_t peer_connection_server, peer_connection_client;


peer_connection_t *pc = &peer_connection_client;

void mqtt_offer_publish(char *sdp_content) {
    cJSON *signal = cJSON_CreateObject();
    cJSON_AddStringToObject(signal, "type", "offer");
    cJSON_AddStringToObject(signal, "sdp", sdp_content);
    paho_mqtt_publish(&client, QOS1, MQTT_PUBTOPIC, cJSON_Print(signal));
    aos_msleep(1000);
    cJSON_Delete(signal);
}

void mqtt_answer_publish(char *sdp_content) {
    cJSON *signal = cJSON_CreateObject();
    cJSON_AddStringToObject(signal, "type", "answer");
    cJSON_AddStringToObject(signal, "sdp", sdp_content);
    paho_mqtt_publish(&client, QOS1, MQTT_PUBTOPIC, cJSON_Print(signal));
    aos_msleep(1000);
    cJSON_Delete(signal);
}

void mqtt_candidate_publish(char *sdp_content) {
    cJSON *signal = cJSON_CreateObject();
    cJSON_AddStringToObject(signal, "type", "candidate");
    cJSON_AddStringToObject(signal, "candidate", sdp_content);
    cJSON_AddNumberToObject(signal, "sdpMLineIndex", 0);
    cJSON_AddStringToObject(signal, "sdpMid", "0");
    paho_mqtt_publish(&client, QOS1, MQTT_PUBTOPIC, cJSON_Print(signal));
    aos_msleep(1000);
    cJSON_Delete(signal);
}

static void mqtt_sub_callback(MQTTClient *c, MessageData *msg_data)
{
    
    *((char *)msg_data->message->payload + msg_data->message->payloadlen) = '\0';
    JLOG_INFO("mqtt sub callback: %.*s %.*s",
               msg_data->topicName->lenstring.len,
               msg_data->topicName->lenstring.data,
               msg_data->message->payloadlen,
               (char *)msg_data->message->payload);

    strncpy(cmd_buf, (char *)msg_data->message->payload, SDP_CONTENT_LENGTH);
    cJSON *cmd = cJSON_Parse(cmd_buf);
    if (cmd) {
        char *cmd_type = cJSON_GetObjectItem(cmd, "type")->valuestring;
        if (cmd_type) {
            JLOG_INFO("type: %s", cmd_type);
            if (strstr(cmd_type,"offer")) {
                char *sdp_string = cJSON_GetObjectItem(cmd, "sdp")->valuestring;
                if (sdp_string) {
                    JLOG_INFO("%s", sdp_string);
                    juice_set_remote_description(pc->juice_agent, sdp_string);
                }
            }
            if (strstr(cmd_type,"candidate")) {            
                char *candidate_string = cJSON_GetObjectItem(cmd, "candidate")->valuestring;
                if (candidate_string) {
                    JLOG_INFO("%s", candidate_string);
                    juice_add_remote_candidate(pc->juice_agent, candidate_string);
                }
            }
        }
        
    }
}

static void mqtt_sub_default_callback(MQTTClient *c, MessageData *msg_data)
{
    *((char *)msg_data->message->payload + msg_data->message->payloadlen) = '\0';
    JLOG_INFO("mqtt sub default callback: %.*s %.*s",
               msg_data->topicName->lenstring.len,
               msg_data->topicName->lenstring.data,
               msg_data->message->payloadlen,
               (char *)msg_data->message->payload);
}

static void mqtt_connect_callback(MQTTClient *c)
{
    JLOG_INFO("inter mqtt_connect_callback!");
}

static void mqtt_online_callback(MQTTClient *c)
{
    JLOG_INFO("inter mqtt_online_callback!");
}

static void mqtt_offline_callback(MQTTClient *c)
{
    JLOG_INFO("inter mqtt_offline_callback!");
}

static int mqtt_start(int argc, char **argv)
{
    /* init condata param by using MQTTPacket_connectData_initializer */
    MQTTPacket_connectData condata = MQTTPacket_connectData_initializer;
    // static char cid[20] = { 0 };

    if (argc != 1)
    {
        JLOG_ERROR("mqtt_start    --start a mqtt worker thread.\n");
        return -1;
    }

    if (is_started)
    {
        JLOG_ERROR("mqtt client is already connected.");
        return -1;
    }
    /* config MQTT context param */
    {
        client.isconnected = 0;
        client.uri = MQTT_URI;

        /* generate the random client ID */
        // snprintf(cid, sizeof(cid), "mqtt_%d", (uint32_t)aos_now_ms());
        /* config connect param */
        memcpy(&client.condata, &condata, sizeof(condata));
        client.condata.clientID.cstring = MQTT_CLIENTID;
        client.condata.keepAliveInterval = 30;
        client.condata.cleansession = 1;
        client.condata.username.cstring = MQTT_USERNAME;
        client.condata.password.cstring = MQTT_PASSWORD;

        /* config MQTT will param. */
        client.condata.willFlag = MQTT_WILLFLAG;
        client.condata.will.qos = 1;
        client.condata.will.retained = 0;
        client.condata.will.topicName.cstring = MQTT_PUBTOPIC;
        client.condata.will.message.cstring = MQTT_WILLMSG;

        /* rt_malloc buffer. */
        client.buf_size = client.readbuf_size = MQTT_CLIENT_BUF_SIZE;
        // if (!(client.buf && client.readbuf))
        // {
        //     JLOG_ERROR("no memory for MQTT client buffer!");
        //     return -1;
        // }

        /* set event callback function */
        client.connect_callback = mqtt_connect_callback;
        client.online_callback = mqtt_online_callback;
        client.offline_callback = mqtt_offline_callback;

        /* set subscribe table and event callback */
        client.messageHandlers[0].topicFilter = alloc_string_copy(MQTT_SUBTOPIC, NULL);
        client.messageHandlers[0].callback = mqtt_sub_callback;
        client.messageHandlers[0].qos = QOS1;

        /* set default subscribe event callback */
        client.defaultMessageHandler = mqtt_sub_default_callback;
    }

    /* run mqtt client */
    paho_mqtt_start(&client);
    is_started = 1;

    return 0;
}

static int mqtt_stop(int argc, char **argv)
{
    if (argc != 1)
    {
        JLOG_ERROR("mqtt_stop    --stop mqtt worker thread and free mqtt client object.\n");
    }

    is_started = 0;

    return paho_mqtt_stop(&client);
}

static int mqtt_ping(int argc, char **argv)
{
    if (argc != 1)
    {
        JLOG_ERROR("mqtt_ping    --ping mqtt server.\n");
    }

    is_started = 0;

    return paho_mqtt_ping(&client);
}

static int mqtt_cycle(int argc, char **argv)
{
    if (argc != 1)
    {
        JLOG_ERROR("mqtt_cycle    --cycle mqtt receive.\n");
    }

    is_started = 0;

    return paho_mqtt_cycle(&client);
}

static int mqtt_publish(int argc, char **argv)
{
    if (is_started == 0)
    {
        JLOG_ERROR("mqtt client is not connected.");
        return -1;
    }

    if (argc == 2)
    {
        paho_mqtt_publish(&client, QOS1, MQTT_PUBTOPIC, argv[1]);
    }
    else if (argc == 3)
    {
        paho_mqtt_publish(&client, QOS1, argv[1], argv[2]);
    }
    else
    {
        JLOG_ERROR("mqtt_publish <topic> [message]  --mqtt publish message to specified topic.\n");
        return -1;
    }

    return 0;
}

static void mqtt_new_sub_callback(MQTTClient *client, MessageData *msg_data)
{
    *((char *)msg_data->message->payload + msg_data->message->payloadlen) = '\0';
    JLOG_INFO("mqtt new subscribe callback: %.*s %.*s",
               msg_data->topicName->lenstring.len,
               msg_data->topicName->lenstring.data,
               msg_data->message->payloadlen,
               (char *)msg_data->message->payload);
}

static int mqtt_subscribe(int argc, char **argv)
{
    if (argc != 2)
    {
        JLOG_ERROR("mqtt_subscribe [topic]  --send an mqtt subscribe packet and wait for suback before returning.\n");
        return -1;
    }

    if (is_started == 0)
    {
        JLOG_ERROR("mqtt client is not connected.");
        return -1;
    }

    return paho_mqtt_subscribe(&client, QOS1, argv[1], mqtt_new_sub_callback);
}

static int mqtt_unsubscribe(int argc, char **argv)
{
    if (argc != 2)
    {
        JLOG_ERROR("mqtt_unsubscribe [topic]  --send an mqtt unsubscribe packet and wait for suback before returning.\n");
        return -1;
    }

    if (is_started == 0)
    {
        JLOG_ERROR("mqtt client is not connected.");
        return -1;
    }

    return paho_mqtt_unsubscribe(&client, argv[1]);
}

ALIOS_CLI_CMD_REGISTER(mqtt_start, mqtt_start, startup mqtt client);
ALIOS_CLI_CMD_REGISTER(mqtt_stop, mqtt_stop, stop mqtt client);
ALIOS_CLI_CMD_REGISTER(mqtt_ping, mqtt_ping, ping mqtt server);
ALIOS_CLI_CMD_REGISTER(mqtt_cycle, mqtt_cycle, cycle mqtt receive);
ALIOS_CLI_CMD_REGISTER(mqtt_publish, mqtt_publish, mqtt publish message to specified topic);
ALIOS_CLI_CMD_REGISTER(mqtt_subscribe,  mqtt_subscribe, mqtt subscribe topic);
ALIOS_CLI_CMD_REGISTER(mqtt_unsubscribe, mqtt_unsubscribe, mqtt unsubscribe topic);
