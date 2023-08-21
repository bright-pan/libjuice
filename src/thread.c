#include "thread.h"

thread_attr_t thread_attr_default = {
	.stacksize                 = THREAD_DEFAULT_STACK_SIZE,
    .sched_priority            = THREAD_DEFAULT_PRIORITY,
    .sched_slice               = THREAD_DEFAULT_SLICE,
    .detachstate               = THREAD_CREATE_JOINABLE,
    .contentionscope           = THREAD_SCOPE_SYSTEM,
    .inheritsched              = THREAD_EXPLICIT_SCHED,
    .guardsize                 = THREAD_DEFAULT_GUARD_SIZE,
    .stackaddr                 = NULL,
    .flag                      = THREAD_DYN_INIT
};

int mutex_init_impl(mutex_t *m, int flags) {
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, flags);
	int ret = pthread_mutex_init(m, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
	return ret;
}

void thread_attr_init(thread_attr_t *attr, int prio, int ssize) {
    pthread_attr_init(attr);
    attr->sched_priority = prio;
    attr->stacksize = ssize;
}