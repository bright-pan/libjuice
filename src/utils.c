#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif


char *alloc_string_copy(const char *orig, bool *alloc_failed) {
	if (!orig)
		return NULL;

	char *copy = juice_malloc(strlen(orig) + 1);
	if (!copy) {
		if (alloc_failed)
			*alloc_failed = true;

		return NULL;
	}
	strcpy(copy, orig);
	return copy;
}
