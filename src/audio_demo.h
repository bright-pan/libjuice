#ifndef __AUDIO_DEMO__
#define __AUDIO_DEMO__

#define PCM_DEMO_LENGTH 193932

#define READ_PERIOD_SIZE 1280
#define READ_BUFFER_SIZE (READ_PERIOD_SIZE * 2 * 2)

int audio_demo_readi(unsigned char *dst);

#endif
