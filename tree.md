├── cmake
├── include
│   └── juice
│       ├── codec.h //编码配置
│       ├── juice_config.h //基本常用配置信息
│       ├── juice.h // 对外输出接口
│       └── juice_log.h // 对外输出日志模块
├── LICENSE
├── Makefile
├── package.yaml
├── README.md
├── src
│   ├── addr.c // 地址信息
│   ├── addr.h
│   ├── agent.c // ice agent 处理
│   ├── agent.h
│   ├── audio_demo.c // 音频demo数据文件及相关读取函数，用于音频调试。
│   ├── audio_demo.h
│   ├── base64.c // base64编码, 用于ice协议处理
│   ├── base64.h
│   ├── conn.c // ICE链接处理
│   ├── conn.h
│   ├── conn_mux.c // Agent数据链接处理为mux方式。
│   ├── conn_mux.h
│   ├── conn_poll.c // Agent数据链接处理为poll方式。
│   ├── conn_poll.h
│   ├── conn_thread.c // Agent数据链接处理为thread方式。
│   ├── conn_thread.h
│   ├── const_time.c // 通用时间处理函数
│   ├── const_time.h
│   ├── crc32.c // stun协议crc校验
│   ├── crc32.h
│   ├── dtls_srtp.c // dtls strp链接建立及握手
│   ├── dtls_srtp.h
│   ├── getnameinfo.c // lwip补充IP处理函数。
│   ├── getnameinfo.h
│   ├── hash.c // hash算法抽象层
│   ├── hash.h
│   ├── hmac.c // HMAC算法抽象层
│   ├── hmac.h
│   ├── ice.c // ice协议实现层
│   ├── ice.h
│   ├── juice.c // 对外暴露接口层
│   ├── log.c // 日志处理
│   ├── log.h
│   ├── packet.c // fifo打包
│   ├── packet.h
│   ├── paho_mqtt.h
│   ├── paho_mqtt_udp.c // mqtt传输sdp
│   ├── peer_connection.c // peer链接处理层
│   ├── peer_connection.h
│   ├── picohash.h
│   ├── pipe.c // sdp管道处理层
│   ├── pipe.h
│   ├── random.c // 随机数抽象层
│   ├── random.h
│   ├── ring_fifo.c // ring buffer
│   ├── ring_fifo.h
│   ├── rtcp_packet.c // rtcp包处理
│   ├── rtcp_packet.h
│   ├── rtp.c // rtp包处理
│   ├── rtp_enc.c //音视频编码层
│   ├── rtp_enc.h
│   ├── rtp.h
│   ├── rtp_list.c //rtp抖动缓冲区处理层
│   ├── rtp_list.h
│   ├── sctp.c //sctp协议处理层
│   ├── sctp.h
│   ├── sdp.c //sdp协议处理层
│   ├── sdp.h
│   ├── server.c //打洞服务
│   ├── server.h
│   ├── socket.h //socket 抽象处理
│   ├── stun.c //stun协议处理
│   ├── stun.h
│   ├── tasklist.md 协议栈常用任务列表
│   ├── thread.c // posix thread抽象层
│   ├── thread.h
│   ├── timestamp.c // 时间戳抽象层
│   ├── timestamp.h
│   ├── turn.c // turn协议处理
│   ├── turn.h
│   ├── udp.c // udp抽象层
│   ├── udp.h
│   ├── uthash.h // 哈希链表处理层
│   ├── utils.c // 通用处理函数
│   └── utils.h
├── TAGS
└── test
    ├── answer.log // answer sdp
    ├── base64.c
    ├── bind.c
    ├── conflict.c
    ├── connectivity.c
    ├── crc32.c
    ├── gathering.c
    ├── grammar.js
    ├── index.js
    ├── main.js
    ├── mqtt.min.js
    ├── mux.c
    ├── notrickle.c
    ├── offer.log
    ├── parser.js
    ├── sdp.log
    ├── server.c
    ├── stun.c
    ├── test_config.h
    ├── test_dtls.c
    ├── test_juice.c
    ├── test_mqtt.c
    ├── test_peer_connection.c //webrtc demo使用方法
    ├── test_udp_client.c
    ├── test_udp_server.c
    ├── test_uthash.c
    ├── thread.c
    ├── turn.c
    ├── webrtc_mqtt.html // web端使用页面
    └── writer.js