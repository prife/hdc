#ifndef STARTUP_SYSPARAM_PARAMETER_API_H
#define STARTUP_SYSPARAM_PARAMETER_API_H
#include <stdint.h>
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define PARAM_CONST_VALUE_LEN_MAX 4096
#define PARAM_VALUE_LEN_MAX  96
#define PARAM_NAME_LEN_MAX  96
#define OS_FULL_NAME_LEN 128
#define VERSION_ID_MAX_LEN 256
#define PARAM_BUFFER_MAX (0x01 << 16)

static const char EMPTY_STR[] = { "" };

inline int GetParameter(const char *key, const char *def, char *value, uint32_t len) {}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif // STARTUP_SYSPARAM_PARAMETER_API_H