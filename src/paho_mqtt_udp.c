#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include <string.h>
#include <stdint.h>

#include <aos/kernel.h>
#include <sys/time.h>


#include <lwip/netdb.h>
#include <sys/socket.h>
#include <arch/sys_arch.h>
#include <lwip/sys.h>
#include <lwip/netifapi.h>
#include <MQTTPacket.h>
#include "paho_mqtt.h"
#include "utils.h"
#include "log.h"


#ifndef MQTT_THREAD_STACK_SIZE
#ifdef MQTT_USING_TLS
#define MQTT_THREAD_STACK_SIZE 6144
#else
#define MQTT_THREAD_STACK_SIZE 4096
#endif
#endif

#ifdef MQTT_USING_TLS
#if (MQTT_THREAD_STACK_SIZE < 6144)
#error "MQTT using tls, please increase MQTT thread stack size up to 6K via menuconfig tool!"
#endif
#endif

static uint16_t pub_port = 7000;

/*
 * resolve server address
 * @param server the server sockaddress
 * @param url the input URL address.
 * @param host_addr the buffer pointer to save server host address
 * @param request the pointer to point the request url, for example, /index.html
 *
 * @return 0 on resolve server address OK, others failed
 *
 * URL example:
 * tcp://192.168.10.151:1883
 * tls://192.168.10.151:61614
 * tcp://[fe80::20c:29ff:fe9a:a07e]:1883
 * tls://[fe80::20c:29ff:fe9a:a07e]:61614
 */
static int mqtt_resolve_uri(MQTTClient *c, struct addrinfo **res)
{
    int rc = 0;
    int uri_len = 0, host_addr_len = 0, port_len = 0;
    char *ptr;
    char port_str[6] = {0};      /* default port of mqtt(http) */

    const char *host_addr = 0;
    char *host_addr_new = NULL;
    const char *uri = c->uri;
    uri_len = strlen(uri);

    /* strip protocol(tcp or ssl) */
    if (strncmp(uri, "tcp://", 6) == 0)
    {
        host_addr = uri + 6;
    }
    else if(strncmp(uri, "ssl://", 6) == 0)
    {
        host_addr = uri + 6;
    }
    else
    {
        rc = -1;
        goto _exit;
    }

    /* ipv6 address */
    if (host_addr[0] == '[')
    {
        host_addr += 1;
        ptr = strstr(host_addr, "]");
        if (!ptr)
        {
            rc = -1;
            goto _exit;
        }
        host_addr_len = ptr - host_addr;
        if ((host_addr_len < 1) || (host_addr_len > uri_len))
        {
            rc = -1;
            goto _exit;
        }

        port_len = uri_len - 6 - host_addr_len - 3;
        if (port_len >= 6 || port_len < 1)
        {
            rc = -1;
            goto _exit;
        }

        strncpy(port_str, host_addr + host_addr_len + 2, port_len);
        port_str[port_len] = '\0';
        JLOG_INFO("ipv6 address port: %s\n", port_str);
    }
    else /* ipv4 or domain. */
    {
        ptr = strstr(host_addr, ":");
        if (!ptr)
        {
            rc = -1;
            goto _exit;
        }
        host_addr_len = ptr - host_addr;
        if ((host_addr_len < 1) || (host_addr_len > uri_len))
        {
            rc = -1;
            goto _exit;
        }

        port_len = uri_len - 6 - host_addr_len - 1;
        if (port_len >= 6 || port_len < 1)
        {
            rc = -1;
            goto _exit;
        }

        strncpy(port_str, host_addr + host_addr_len + 1, port_len);
        port_str[port_len] = '\0';
        JLOG_INFO("ipv4 address port: %s\n", port_str);
    }

    /* get host addr ok. */
    {
        /* resolve the host name. */
        struct addrinfo hint;
        int ret;

        host_addr_new = juice_malloc(host_addr_len + 1);

        if (!host_addr_new)
        {
            rc = -1;
            goto _exit;
        }

        memcpy(host_addr_new, host_addr, host_addr_len);
        host_addr_new[host_addr_len] = '\0';
        JLOG_INFO("HOST =  '%s'\n", host_addr_new);

        memset(&hint, 0, sizeof(hint));

        ret = getaddrinfo(host_addr_new, port_str, &hint, res);
        if (ret != 0)
        {
            JLOG_INFO("getaddrinfo err: %d '%s'\n", ret, host_addr_new);
            rc = -1;
            goto _exit;
        }
    }

_exit:
    if (host_addr_new != NULL)
    {
        juice_free(host_addr_new);
        host_addr_new = NULL;
    }
    return rc;
}

static int net_connect(MQTTClient *c)
{
    int rc = -1;
    struct addrinfo *addr_res = NULL;

    c->sock = -1;
    c->next_packetid = 0;

    rc = mqtt_resolve_uri(c, &addr_res);
    if (rc < 0 || addr_res == NULL)
    {
        JLOG_INFO("resolve uri err\n");
        goto _exit;
    }

    if ((c->sock = socket(addr_res->ai_family, SOCK_STREAM, 0)) == -1)
    {
        JLOG_INFO("create socket error!\n");
        goto _exit;
    }

    if ((rc = connect(c->sock, addr_res->ai_addr, addr_res->ai_addrlen)) == -1)
    {
        JLOG_INFO("connect err!\n");
        closesocket(c->sock);
        c->sock = -1;
        rc = -2;
        goto _exit;
    }

_exit:
    if (addr_res)
    {
        freeaddrinfo(addr_res);
        addr_res = NULL;
    }
    return rc;
}

static int net_disconnect(MQTTClient *c)
{
    if (c->sock >= 0)
    {
        closesocket(c->sock);
        c->sock = -1;
    }

    return 0;
}

static int net_disconnect_exit(MQTTClient *c)
{
    int i;

    net_disconnect(c);

    if (c->buf && c->readbuf)
    {
        juice_free(c->buf);
        juice_free(c->readbuf);
    }

    if (aos_sem_is_valid(&c->pub_sem))
    {
        aos_sem_free(&c->pub_sem);
    }

    if (c->pub_sock >= 0)
    {
        closesocket(c->pub_sock);
        c->pub_sock = -1;
    }

    for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
    {
        if (c->messageHandlers[i].topicFilter)
        {
            juice_free(c->messageHandlers[i].topicFilter);
            c->messageHandlers[i].topicFilter = NULL;
            c->messageHandlers[i].callback = NULL;
        }
    }

    c->isconnected = 0;

    return 0;
}

static int sendPacket(MQTTClient *c, int length)
{
    int rc;
    struct timeval tv;

    tv.tv_sec = 2000;
    tv.tv_usec = 0;

    setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
    rc = send(c->sock, c->buf, length, 0);
    if (rc == length)
    {
        rc = 0;
    }
    else
    {
        rc = -1;
    }

    return rc;
}

static int net_read(MQTTClient *c, unsigned char *buf,  int len, int timeout)
{
    int bytes = 0;
    int rc, ret;
    fd_set readset;

    // struct timeval tv;

    // tv.tv_sec = 0;
    // tv.tv_usec = 100*1000;

    // setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

    struct timeval interval;

    interval.tv_sec = 0;
    interval.tv_usec = 1000000;

    while (bytes < len)
    {
        rc = recv(c->sock, &buf[bytes], (size_t)(len - bytes), MSG_DONTWAIT);

        if (rc == -1)
        {
            if (errno == ENOTCONN || errno == ECONNRESET)
            {
                bytes = -1;
                break;
            }
        }
        else
            bytes += rc;

        if (bytes >= len)
        {
            break;
        }

        if (timeout > 0)
        {
            while (1) {
                timeout  -= 100;
                JLOG_VERBOSE("net_read %d:%d, timeout:%d\n", bytes, len, timeout);
                // setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

                FD_ZERO(&readset);
                FD_SET(c->sock, &readset);

                ret = select(c->sock + 1, &readset, NULL, NULL, &interval);
                if (ret == 0) {
                    // timeout
                    continue;
                } else {
                    break;
                }
            }
        }
        else
        {
            JLOG_INFO("net_read %d:%d, break!\n", bytes, len);
            break;
        }
    }

    return bytes;
}

static int decodePacket(MQTTClient *c, int *value, int timeout)
{
    unsigned char i;
    int multiplier = 1;
    int len = 0;
    const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

    *value = 0;
    do
    {
        int rc = MQTTPACKET_READ_ERROR;

        if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES)
        {
            rc = MQTTPACKET_READ_ERROR; /* bad data */
            goto exit;
        }
        rc = net_read(c, &i, 1, timeout);
        if (rc != 1)
            goto exit;
        *value += (i & 127) * multiplier;
        multiplier *= 128;
    }
    while ((i & 128) != 0);
exit:
    return len;
}

static int MQTTPacket_readPacket(MQTTClient *c)
{
    int rc = PAHO_FAILURE;
    MQTTHeader header = {0};
    int len = 0;
    int rem_len = 0;

    /* 1. read the header byte.  This has the packet type in it */
    if (net_read(c, c->readbuf, 1, 0) != 1)
        goto exit;

    len = 1;
    /* 2. read the remaining length.  This is variable in itself */
    decodePacket(c, &rem_len, 50);
    len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

    if (len + rem_len > c->readbuf_size) {
        JLOG_FATAL("packet read is too large: length:%d ,readbuf_size:%d", len + rem_len, c->readbuf_size);
        goto exit;
    }
    /* 3. read the rest of the buffer using a callback to supply the rest of the data */
    if (rem_len > 0 && (net_read(c, c->readbuf + len, rem_len, rem_len + 1000) != rem_len))
        goto exit;

    header.byte = c->readbuf[0];
    rc = header.bits.type;

exit:
    return rc;
}

static int getNextPacketId(MQTTClient *c)
{
    return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}

static int MQTTConnect(MQTTClient *c)
{
    int rc = -1, len;
    MQTTPacket_connectData *options = &c->condata;

    if (c->isconnected) /* don't send connect packet again if we are already connected */
        goto _exit;

    c->keepAliveInterval = options->keepAliveInterval;

    if ((len = MQTTSerialize_connect(c->buf, c->buf_size, options)) <= 0)
        goto _exit;

    if ((rc = sendPacket(c, len)) != 0)  // send the connect packet
        goto _exit; // there was a problem

    {
        int res;
        fd_set readset;
        struct timeval timeout;

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(c->sock, &readset);

        res = select(c->sock + 1, &readset, NULL, NULL, &timeout);

        if (res <= 0)
        {
            JLOG_INFO("%s wait resp fail, res:%d errno:%d\n", __FUNCTION__, res, errno);
            rc = -1;
            goto _exit;
        }
    }

    rc = MQTTPacket_readPacket(c);
    if (rc < 0)
    {
        JLOG_INFO("%s MQTTPacket_readPacket fail\n", __FUNCTION__);
        goto _exit;
    }

    if (rc == CONNACK)
    {
        unsigned char sessionPresent, connack_rc;

        if (MQTTDeserialize_connack(&sessionPresent, &connack_rc, c->readbuf, c->readbuf_size) == 1)
        {
            rc = connack_rc;
        }
        else
        {
            rc = -1;
        }
    }
    else
        rc = -1;

_exit:
    if (rc == 0)
        c->isconnected = 1;

    return rc;
}

static int MQTTDisconnect(MQTTClient *c)
{
    int rc = PAHO_FAILURE;
    int len = 0;

    len = MQTTSerialize_disconnect(c->buf, c->buf_size);
    if (len > 0)
        rc = sendPacket(c, len);            // send the disconnect packet

    c->isconnected = 0;

    return rc;
}

/**
 * This function subscribe specified mqtt topic.
 *
 * @param c the pointer of MQTT context structure
 * @param topicFilter topic filter name
 * @param qos requested QoS
 *
 * @return the error code, 0 on subscribe successfully.
 */
static int MQTTSubscribe(MQTTClient *c, const char *topicFilter, enum QoS qos)
{
    int rc = PAHO_FAILURE;
    int len = 0;
    int qos_sub = qos;
    MQTTString topic = MQTTString_initializer;
    topic.cstring = (char *)topicFilter;

    if (!c->isconnected)
        goto _exit;

    len = MQTTSerialize_subscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic, &qos_sub);
    if (len <= 0)
        goto _exit;
    if ((rc = sendPacket(c, len)) != PAHO_SUCCESS) // send the subscribe packet
        goto _exit;             // there was a problem

    {
        int res;
        fd_set readset;
        struct timeval timeout;

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(c->sock, &readset);

        res = select(c->sock + 1, &readset, NULL, NULL, &timeout);

        if (res <= 0)
        {
            JLOG_INFO("%s wait resp fail, res:%d errno:%d\n", __FUNCTION__, res, errno);
            rc = -1;
            goto _exit;
        }
    }

    rc = MQTTPacket_readPacket(c);
    if (rc < 0)
    {
        JLOG_INFO("MQTTPacket_readPacket MQTTConnect fail\n");
        goto _exit;
    }

    if (rc == SUBACK)      // wait for suback
    {
        int count = 0, grantedQoS = -1;
        unsigned short mypacketid;

        if (MQTTDeserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
            rc = grantedQoS; // 0, 1, 2 or 0x80

        if (rc != 0x80)
        {
            rc = 0;
        }
    }
    else
        rc = PAHO_FAILURE;

_exit:
    return rc;
}

static void NewMessageData(MessageData *md, MQTTString *aTopicName, MQTTMessage *aMessage)
{
    md->topicName = aTopicName;
    md->message = aMessage;
}

// assume topic filter and name is in correct format
// # can only be at end
// + and # can only be next to separator
static char isTopicMatched(char *topicFilter, MQTTString *topicName)
{
    char *curf = topicFilter;
    char *curn = topicName->lenstring.data;
    char *curn_end = curn + topicName->lenstring.len;

    while (*curf && curn < curn_end)
    {
        if (*curn == '/' && *curf != '/')
            break;
        if (*curf != '+' && *curf != '#' && *curf != *curn)
            break;
        if (*curf == '+')
        {
            // skip until we meet the next separator, or end of string
            char *nextpos = curn + 1;
            while (nextpos < curn_end && *nextpos != '/')
                nextpos = ++curn + 1;
        }
        else if (*curf == '#')
            curn = curn_end - 1;    // skip until end of string
        curf++;
        curn++;
    };

    return (curn == curn_end) && (*curf == '\0');
}

static int deliverMessage(MQTTClient *c, MQTTString *topicName, MQTTMessage *message)
{
    int i;
    int rc = PAHO_FAILURE;

    // we have to find the right message handler - indexed by topic
    for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
    {
        if (c->messageHandlers[i].topicFilter != 0 && (MQTTPacket_equals(topicName, (char *)c->messageHandlers[i].topicFilter) ||
                isTopicMatched((char *)c->messageHandlers[i].topicFilter, topicName)))
        {
            if (c->messageHandlers[i].callback != NULL)
            {
                MessageData md;
                NewMessageData(&md, topicName, message);
                c->messageHandlers[i].callback(c, &md);
                rc = PAHO_SUCCESS;
            }
        }
    }

    if (rc == PAHO_FAILURE && c->defaultMessageHandler != NULL)
    {
        MessageData md;
        NewMessageData(&md, topicName, message);
        c->defaultMessageHandler(c, &md);
        rc = PAHO_SUCCESS;
    }

    return rc;
}

static int MQTT_cycle(MQTTClient *c)
{
    // read the socket, see what work is due
    int packet_type = MQTTPacket_readPacket(c);

    int len = 0,
        rc = PAHO_SUCCESS;


    if (packet_type == -1)
    {
        rc = PAHO_FAILURE;
        goto exit;
    }

    switch (packet_type)
    {
    case CONNACK:
    case PUBACK:
    case SUBACK:
    {
        int count = 0, grantedQoS = -1;
        unsigned short mypacketid;

        if (MQTTDeserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
            rc = grantedQoS; // 0, 1, 2 or 0x80

        if (rc != 0x80)
            rc = 0;

        break;
    }
    case PUBLISH:
    {
        MQTTString topicName;
        MQTTMessage msg;
        int intQoS;
        if (MQTTDeserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
                                    (unsigned char **)&msg.payload, (int *)&msg.payloadlen, c->readbuf, c->readbuf_size) != 1)
            goto exit;
        msg.qos = (enum QoS)intQoS;
        deliverMessage(c, &topicName, &msg);
        if (msg.qos != QOS0)
        {
            if (msg.qos == QOS1)
                len = MQTTSerialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
            else if (msg.qos == QOS2)
                len = MQTTSerialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
            if (len <= 0)
                rc = PAHO_FAILURE;
            else
                rc = sendPacket(c, len);
            if (rc == PAHO_FAILURE)
                goto exit; // there was a problem
        }
        break;
    }
    case PUBREC:
    {
        unsigned short mypacketid;
        unsigned char dup, type;
        if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
            rc = PAHO_FAILURE;
        else if ((len = MQTTSerialize_ack(c->buf, c->buf_size, PUBREL, 0, mypacketid)) <= 0)
            rc = PAHO_FAILURE;
        else if ((rc = sendPacket(c, len)) != PAHO_SUCCESS) // send the PUBREL packet
            rc = PAHO_FAILURE; // there was a problem
        if (rc == PAHO_FAILURE)
            goto exit; // there was a problem
        break;
    }
    case PUBCOMP:
        break;
    case PINGRESP:
        c->tick_ping = aos_now_ms();
        c->ping_flag = 0;
        break;
    }

exit:
    return rc;
}

static int MQTT_local_send(MQTTClient *c, const void *data, int len)
{
    struct sockaddr_in server_addr = {0};
    int send_len;
    struct in_addr *addr = (struct in_addr *)&netif_default->ip_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(c->pub_port);
    server_addr.sin_addr = *addr;
    memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));

    send_len = sendto(c->pub_sock, data, len, MSG_DONTWAIT,
                      (struct sockaddr *)&server_addr, sizeof(struct sockaddr));

    return send_len;
}

/*
MQTT_CMD:
"DISCONNECT"
*/
int MQTT_CMD(MQTTClient *c, const char *cmd)
{
    char *data = 0;
    int cmd_len, len;
    int rc = PAHO_FAILURE;

    if (!c->isconnected)
        goto _exit;

    cmd_len = strlen(cmd) + 1;
    if (cmd_len >= sizeof(MQTTMessage))
    {
        JLOG_INFO("cmd too loog %d:\n", cmd_len, sizeof(MQTTMessage));
        goto _exit;
    }

    data = juice_malloc(cmd_len);
    if (!data)
        goto _exit;

    strcpy(data, cmd);
    len = MQTT_local_send(c, data, cmd_len);
    if (len == cmd_len)
    {
        rc = 0;
    }

_exit:
    if (data)
        juice_free(data);

    return rc;
}

/**
 * This function publish message to specified mqtt topic.
 * [MQTTMessage] + [payload] + [topic] + '\0'
 *
 * @param client the pointer of MQTT context structure
 * @param topic topic filter name
 * @param message the pointer of MQTTMessage structure
 *
 * @return the error code, 0 on subscribe successfully.
 */
int MQTTPublish(MQTTClient *client, const char *topic, MQTTMessage *message)
{
    int rc = PAHO_FAILURE;
    int len, msg_len;
    char *data = 0;

    if (!client->isconnected)
        goto exit;

    msg_len = sizeof(MQTTMessage) + message->payloadlen + strlen(topic) + 1;
     if(msg_len >= client->buf_size)
    {
        JLOG_INFO("Message is too long %d:%d.", msg_len, client->buf_size);
        rc = PAHO_BUFFER_OVERFLOW;
        goto exit;
    }

    data = juice_malloc(msg_len);
    if (!data)
        goto exit;

    memcpy(data, message, sizeof(MQTTMessage));
    memcpy(data + sizeof(MQTTMessage), message->payload, message->payloadlen);
    strcpy(data + sizeof(MQTTMessage) + message->payloadlen, topic);

    len = MQTT_local_send(client, data, msg_len);
    if (len == msg_len)
    {
        rc = PAHO_SUCCESS;
    }
    //JLOG_INFO("MQTTPublish sendto %d\n", len);

exit:
    if (data)
        juice_free(data);

    return rc;
}

static void paho_mqtt_thread(void *param)
{
    MQTTClient *c = (MQTTClient *)param;
    int i, rc, len;
    int rc_t = 0;

    c->pub_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (c->pub_sock == -1)
    {
        JLOG_INFO("create pub_sock error!\n");
        goto _mqtt_exit;
    }

    /* bind publish socket. */
    {
        struct sockaddr_in pub_server_addr;

        c->pub_port = pub_port;
        pub_port ++;
        pub_server_addr.sin_family = AF_INET;
        pub_server_addr.sin_port = htons((c->pub_port));
        pub_server_addr.sin_addr.s_addr = INADDR_ANY;
        memset(&(pub_server_addr.sin_zero), 0, sizeof(pub_server_addr.sin_zero));
        rc = bind(c->pub_sock, (struct sockaddr *)&pub_server_addr, sizeof(struct sockaddr));
        if (rc == -1)
        {
            JLOG_INFO("pub_sock bind error!\n");
            goto _mqtt_exit;
        }
    }

_mqtt_start:
    if (c->connect_callback)
    {
        c->connect_callback(c);
    }

    rc = net_connect(c);
    if (rc != 0)
    {
        JLOG_ERROR("Net connect error(%d).", rc);
        goto _mqtt_restart;
    }

    rc = MQTTConnect(c);
    if (rc != 0)
    {
        JLOG_ERROR("MQTT connect error(%d): %s.", rc, MQTTSerialize_connack_string(rc));
        goto _mqtt_restart;
    }

    JLOG_INFO("MQTT server connect success.");

    for (i = 0; i < MAX_MESSAGE_HANDLERS; i++)
    {
        const char *topic = c->messageHandlers[i].topicFilter;
        enum QoS qos = c->messageHandlers[i].qos;

        if(topic == NULL)
            continue;

        rc = MQTTSubscribe(c, topic, qos);
        JLOG_INFO("Subscribe #%d %s %s!", i, topic, (rc < 0) || (rc == 0x80) ? ("fail") : ("OK"));

        if (rc != 0)
        {
            if (rc == 0x80)
            {
                JLOG_ERROR("QoS(%d) config err!", qos);
            }
            goto _mqtt_disconnect;
        }
    }

    if (c->online_callback)
    {
        c->online_callback(c);
    }

    c->tick_ping = aos_now_ms();

    int res;
    uint32_t tick_now;
    fd_set readset;
    struct timeval timeout;
    uint32_t ping_time;
    // int ping_flag = 0;

    while (1)
    {
        tick_now = aos_now_ms();
        ping_time = (tick_now - c->tick_ping) / 1000;

        if (ping_time > (c->keepAliveInterval - 5))
        {
            timeout.tv_sec = 5;
            if (!c->ping_flag) {
                c->ping_flag = 1;
                JLOG_VERBOSE("tick close to ping, %d", ping_time);
            } else {
                JLOG_VERBOSE("continue to ping, %d", ping_time);
            }
        }
        else
        {
            timeout.tv_sec = (c->keepAliveInterval - ping_time) / 2;
            JLOG_VERBOSE("timeout for ping: %d, ping_time: %d\n", timeout.tv_sec, ping_time);
        }
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(c->sock, &readset);
        FD_SET(c->pub_sock, &readset);

        /* int select(maxfdp1, readset, writeset, exceptset, timeout); */
        res = select(((c->pub_sock > c->sock) ? c->pub_sock : c->sock) + 1,
                          &readset, NULL, NULL, &timeout);
        if (res == 0 && c->ping_flag)
        {
            if (c->ping_flag++ < 5) {
                len = MQTTSerialize_pingreq(c->buf, c->buf_size);
                rc = sendPacket(c, len);
                if (rc != 0)
                {
                    JLOG_ERROR("[%d] send ping rc: %d \n", aos_now_ms(), rc);
                    // goto _mqtt_disconnect;
                } else {
                    // ping_flag = 0;
                    JLOG_VERBOSE("ping on running time: %ds\n", ping_time);
                }
                // wait Ping Response.
                // timeout.tv_sec = 5;
                // timeout.tv_usec = 0;

                // FD_ZERO(&readset);
                // FD_SET(c->sock, &readset);

                // res = select(c->sock + 1, &readset, NULL, NULL, &timeout);
                // if (res <= 0)
                // {
                //     JLOG_ERROR("[%d] Ping Response timeout res: %d, and disconnect", aos_now_ms(), res);
                //     goto _mqtt_disconnect;
                // }
            } else {
                JLOG_ERROR("Ping Response timeout res: %dS, %d, and disconnect", ping_time, c->ping_flag);
                goto _mqtt_disconnect;
            }
            
        } /* res == 0: timeout for ping. */

        if (res < 0)
        {
            JLOG_ERROR("select res: %d, and disconnect", res);
            goto _mqtt_disconnect;
        }

        if (FD_ISSET(c->sock, &readset))
        {
            JLOG_VERBOSE("sock FD_ISSET\n");
            rc_t = MQTT_cycle(c);
            JLOG_VERBOSE("sock FD_ISSET rc_t : %d\n", rc_t);
            if (rc_t < 0) {
                // goto _mqtt_disconnect;
                JLOG_ERROR("MQTT_cycle process failed");
            }

            continue;
        }

        if (FD_ISSET(c->pub_sock, &readset))
        {
            struct sockaddr_in pub_client_addr;
            uint32_t addr_len = sizeof(struct sockaddr);
            MQTTMessage *message;
            MQTTString topic = MQTTString_initializer;

            JLOG_VERBOSE("pub_sock FD_ISSET\n");

            len = recvfrom(c->pub_sock, c->readbuf, c->readbuf_size, MSG_DONTWAIT,
                           (struct sockaddr *)&pub_client_addr, &addr_len);

            if (pub_client_addr.sin_addr.s_addr != *((uint32_t *)(&netif_default->ip_addr)))
            {
#if 1
                char client_ip_str[16]; /* ###.###.###.### */
                strcpy(client_ip_str,
                       inet_ntoa(*((struct in_addr *) & (pub_client_addr.sin_addr))));
                JLOG_VERBOSE("pub_sock recvfrom len: %s, skip!\n", client_ip_str);
#endif
                continue;
            }

            if (len < sizeof(MQTTMessage))
            {
                c->readbuf[len] = '\0';
                JLOG_VERBOSE("pub_sock recv %d byte: %s\n", len, c->readbuf);

                if (strcmp((const char *)c->readbuf, "DISCONNECT") == 0)
                {
                    JLOG_ERROR("DISCONNECT\n");
                    goto _mqtt_disconnect_exit;
                }

                continue;
            }

            message = (MQTTMessage *)c->readbuf;
            message->payload = c->readbuf + sizeof(MQTTMessage);
            topic.cstring = (char *)c->readbuf + sizeof(MQTTMessage) + message->payloadlen;
            //JLOG_INFO("pub_sock topic:%s, payloadlen:%d\n", topic.cstring, message->payloadlen);

            len = MQTTSerialize_publish(c->buf, c->buf_size, 0, message->qos, message->retained, message->id,
                                        topic, (unsigned char *)message->payload, message->payloadlen);
            if (len <= 0)
            {
                JLOG_ERROR_DUMP_HEX(c->buf, c->buf_size, "MQTTSerialize_publish %s failed, %d", topic.cstring, len);
                // JLOG_ERROR("MQTTSerialize_publish %s failed, %d", topic.cstring, len);
                // goto _mqtt_disconnect;
            }

            if ((rc = sendPacket(c, len)) != PAHO_SUCCESS) // send the subscribe packet
            {
                JLOG_ERROR_DUMP_HEX((unsigned char *)message->payload, message->payloadlen, "sendPacket %s failed, %d", topic.cstring, rc);
                // goto _mqtt_disconnect;
            }
            if (c->isblocking && aos_sem_is_valid(&c->pub_sem))
            {
                aos_sem_free(&c->pub_sem);
            }
        } /* pbulish sock handler. */
    } /* while (1) */

_mqtt_disconnect:
    JLOG_ERROR("MQTT disconnect!\n");
    MQTTDisconnect(c);
_mqtt_restart:
    if (c->offline_callback)
    {
        c->offline_callback(c);
    }

    net_disconnect(c);
    aos_msleep(c->reconnect_interval > 0 ? c->reconnect_interval * 1000 : 1000 * 5);
    JLOG_ERROR("MQTT restart!\n");
    goto _mqtt_start;

_mqtt_disconnect_exit:
    MQTTDisconnect(c);
    net_disconnect_exit(c);

_mqtt_exit:
    JLOG_ERROR("MQTT server is disconnected.");

    return;
}

/**
 * This function start a mqtt worker thread.
 *
 * @param client the pointer of MQTT context structure
 *
 * @return the error code, 0 on start successfully.
 */
int paho_mqtt_start(MQTTClient *client)
{
    int ret;
    static uint8_t counts = 0;
    static char thread_name[64];
    if (client->buf_size > 0 && client->readbuf_size > 0) {
        client->buf = juice_calloc(1, client->buf_size);
        client->readbuf = juice_calloc(1, client->readbuf_size);
        if (client->buf == NULL || client->readbuf == NULL) {
            JLOG_ERROR("no memory for MQTT client buffer!");
            return PAHO_FAILURE;
        }
    }
    /* create publish mutex */
    ret = aos_sem_new(&client->pub_sem, 1);
    if (ret != 0)
    {
        JLOG_ERROR("Create publish semaphore error.");
        return PAHO_FAILURE;
    }

    memset(thread_name, 0x00, sizeof(thread_name));
    snprintf(thread_name, 64, "mqtt%d", counts++);
    ret = aos_task_new(thread_name, paho_mqtt_thread, client, MQTT_THREAD_STACK_SIZE);

    if (ret < 0)
    {
        JLOG_ERROR("Create MQTT thread error.");
        return PAHO_FAILURE;
    }

    return PAHO_SUCCESS;
}

/**
 * This function stop MQTT worker thread and free MQTT client object.
 *
 * @param client the pointer of MQTT context structure
 *
 * @return the error code, 0 on start successfully.
 */
int paho_mqtt_stop(MQTTClient *client)
{
    return MQTT_CMD(client, "DISCONNECT");
}

/**
 * This function send an MQTT subscribe packet and wait for suback before returning.
 *
 * @param client the pointer of MQTT context structure
 * @param qos MQTT Qos type, only support QOS1
 * @param topic topic filter name
 * @param callback the pointer of subscribe topic receive data function
 *
 * @return the error code, 0 on start successfully.
 */
int paho_mqtt_subscribe(MQTTClient *client, enum QoS qos, const char *topic, subscribe_cb callback)
{
    int i, lenght, rc = PAHO_SUCCESS;
    int qos_sub = qos;
    MQTTString topicFilters = MQTTString_initializer;
    topicFilters.cstring = (char *)topic;

    juice_assert(client);
    juice_assert(topic);

    if (qos != QOS1)
    {
        JLOG_ERROR("Not support Qos(%d) config, only support Qos(d).", qos, QOS1);
        return PAHO_FAILURE;
    }

    for (i = 0; i < MAX_MESSAGE_HANDLERS ; ++i)
    {
        if (client->messageHandlers[i].topicFilter &&
                strncmp(client->messageHandlers[i].topicFilter, topic, strlen(topic)) == 0)
        {
            JLOG_INFO("MQTT client topic(%s) is already subscribed.", topic);
            return PAHO_SUCCESS;
        }
    }

    for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
    {
        if (client->messageHandlers[i].topicFilter)
        {
            continue;
        }

        lenght = MQTTSerialize_subscribe(client->buf, client->buf_size, 0, getNextPacketId(client), 1, &topicFilters, &qos_sub);
        if (lenght <= 0)
        {
            JLOG_ERROR("Subscribe #%d %s failed!", i, topic);
            client->isconnected = 0;
            goto _exit;
        }

        rc = sendPacket(client, lenght);
        if (rc != PAHO_SUCCESS)
        {
            JLOG_ERROR("Subscribe #%d %s failed!", i, topic);
            client->isconnected = 0;
            goto _exit;
        }

        client->messageHandlers[i].qos = qos;
        client->messageHandlers[i].topicFilter = alloc_string_copy((char *)topic, NULL);
        if (callback)
        {
            client->messageHandlers[i].callback = callback;
        }

        JLOG_INFO("Subscribe #%d %s OK!", i, topic);
        goto _exit;
    }

    /* check subscribe numble support */
    if (i >= MAX_MESSAGE_HANDLERS)
    {
        JLOG_ERROR("Subscribe MAX_MESSAGE_HANDLERS size(%d) is not enough!", MAX_MESSAGE_HANDLERS);
        rc = PAHO_FAILURE;
        goto _exit;
    }

_exit:
    return rc;
}

/**
 * This function send an MQTT unsubscribe packet and wait for unsuback before returning.
 *
 * @param client the pointer of MQTT context structure
 * @param topic topic filter name
 *
 * @return the error code, 0 on start successfully.
 */
int paho_mqtt_unsubscribe(MQTTClient *client, const char *topic)
{
    int i, length, rc = PAHO_SUCCESS;
    MQTTString topicFilter = MQTTString_initializer;
    topicFilter.cstring = (char *)topic;

    juice_assert(client);
    juice_assert(topic);

    for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
    {
        if (client->messageHandlers[i].topicFilter == NULL ||
                strncmp(client->messageHandlers[i].topicFilter, topic, strlen(topic)) != 0)
        {
            continue;
        }

        length = MQTTSerialize_unsubscribe(client->buf, client->buf_size, 0, getNextPacketId(client), 1, &topicFilter);
        if (length <= 0)
        {
            JLOG_ERROR("Unubscribe #%d %s failed!", i, topic);
            client->isconnected = 0;
            goto _exit;
        }

        rc = sendPacket(client, length);
        if (rc != PAHO_SUCCESS)
        {
            JLOG_ERROR("Unubscribe #%d %s failed!", i, topic);
            client->isconnected = 0;
            goto _exit;
        }

        /* clear message handler */
        if (client->messageHandlers[i].topicFilter)
        {
            juice_free(client->messageHandlers[i].topicFilter);
            client->messageHandlers[i].topicFilter = NULL;
        }
        client->messageHandlers[i].callback = NULL;

        JLOG_INFO("Unsubscribe #%d %s OK!", i, topic);
        goto _exit;
    }

    /* check subscribe topic */
    if (i >= MAX_MESSAGE_HANDLERS)
    {
        JLOG_ERROR("Unsubscribe topic(%s) is not exist!", topic);
        rc = PAHO_FAILURE;
        goto _exit;
    }

_exit:
    return rc;
}

/**
 * This function publish message to specified mqtt topic.
 *
 * @param client the pointer of MQTT context structure
 * @param qos MQTT QOS type, only support QOS1
 * @param topic topic filter name
 * @param msg_str the pointer of MQTTMessage structure
 *
 * @return the error code, 0 on subscribe successfully.
 */
int paho_mqtt_publish(MQTTClient *client, enum QoS qos, const char *topic, const char *msg_str)
{
    MQTTMessage message = {0};

    if (qos != QOS1)
    {
        JLOG_ERROR("Not support Qos(%d) config, only support Qos(d).", qos, QOS1);
        return PAHO_FAILURE;
    }

    message.qos = qos;
    message.retained = 0;
    message.payload = (void *)msg_str;
    message.payloadlen = strlen(message.payload);

    if (client->isblocking && client->pub_sem)
    {
        if(aos_sem_wait(&client->pub_sem, 5 * 1000) < 0)
        {
            return PAHO_FAILURE;
        }
    }

    return MQTTPublish(client, topic, &message);
}

/**
 * This function control MQTT client configure, such as connect timeout, reconnect interval.
 *
 * @param client the pointer of MQTT context structure
 * @param cmd control configure type, 'mqttControl' enumeration shows the supported configure types.
 * @param arg the pointer of argument
 *
 * @return the error code, 0 on subscribe successfully.
 */
int paho_mqtt_control(MQTTClient *client, int cmd, void *arg)
{
    juice_assert(client);
    juice_assert(arg);

    switch (cmd)
    {
        case MQTT_CTRL_SET_CONN_TIMEO:
            client->connect_timeout = *(int *)arg;
            break;

        case MQTT_CTRL_SET_RECONN_INTERVAL:
            client->reconnect_interval = *(int *)arg;
            break;

        case MQTT_CTRL_SET_KEEPALIVE_INTERVAL:
            client->keepAliveInterval = *(unsigned int *)arg;
            break;

        case MQTT_CTRL_PUBLISH_BLOCK:
            client->isblocking = *(int *)arg;
            break;

        default:
            JLOG_ERROR("Input control commoand(%d) error.", cmd);
            break;
    }

    return PAHO_SUCCESS;
}

