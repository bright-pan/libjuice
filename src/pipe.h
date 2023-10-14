#ifndef __PIPE_H__
#define __PIPE_H__

int pipe_send(char *buf, int size);
int pipe_create(char *name, void *param);

#endif