#include <cstdarg>
#include <cstdio>

namespace OHOS::HiviewDFX {
bool IsDebugOn()
{
    return false;
}

bool IsPrivateSwitchOn()
{
    return true;
}
} // namespace OHOS::HiviewDFX

extern "C" {
bool IsDebugOn()
{
    // #error "hello"
    return false;
}

bool IsPrivateSwitchOn()
{
    return true;
}

typedef enum {
    /** Third-party application logs */
    LOG_APP = 0,
} LogType;

typedef enum {
    /** Debug level to be used by {@link OH_LOG_DEBUG} */
    LOG_DEBUG = 3,
    /** Informational level to be used by {@link OH_LOG_INFO} */
    LOG_INFO = 4,
    /** Warning level to be used by {@link OH_LOG_WARN} */
    LOG_WARN = 5,
    /** Error level to be used by {@link OH_LOG_ERROR} */
    LOG_ERROR = 6,
    /** Fatal level to be used by {@link OH_LOG_FATAL} */
    LOG_FATAL = 7,
} LogLevel;

// #include "hilog/log.h"
int HiLogPrintArgs(const LogType type, const LogLevel level, const unsigned int domain, const char *tag,
    const char *fmt, va_list ap) {

    }

int HiLogPrint(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = HiLogPrintArgs(type, level, domain, tag, fmt, ap);
    va_end(ap);
    return ret;
}

}