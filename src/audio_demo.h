#ifndef __AUDIO_DEMO__
#define __AUDIO_DEMO__

#define AUDIO_DEMO_LENGTH 193932

#define AUDIO_DEMO_CHANNEL_NUM 2
#define AUDIO_DEMO_BIT_DEPTH 16

void audio_demo_init(int length, int channel_num, int bit_depth);
int audio_demo_readi(unsigned char *dst, int peroid_size);

#endif
