#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include "log.h"

static log_level_t log_level;
static pthread_mutex_t log_mutex;

int log_init(log_level_t level)
{
    int ret = pthread_mutex_init(&log_mutex, NULL);
    if (ret != 0) {
        return -1;
    }
    log_level = level;
    return 0;
}

void log_puts(int priority, const char *format, ...)
{
    pthread_mutex_lock(&log_mutex);
    /*Windows doesn't support ANSI escape sequences*/
#ifdef WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    WORD textAttributes;
    /* Save current attributes */
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

    switch (priority) {
    case LOG_FATAL:
        /* foreground white, background red */
        textAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_RED;
        break;
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERROR:
        textAttributes = FOREGROUND_RED | FOREGROUND_INTENSITY;
        break;
    case LOG_WARN:
        /* foreground yellow */
        textAttributes = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
        break;
    case LOG_NOTICE:
        textAttributes = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        break;
    default:
        textAttributes = FOREGROUND_GREEN;// | FOREGROUND_INTENSITY;
    }
    SetConsoleTextAttribute(hConsole, textAttributes);
#else
    if(isatty(fileno(stdout))){
        switch (priority) {
        case LOG_FATAL:
            printf("\033[37;41;1m");
            break;
        case LOG_ERROR:
            printf("\033[31m");
            break;
        case LOG_WARN:
            printf("\033[33m");
            break;
        case LOG_INFO:
            printf("\033[32;2m");
            break;
        case LOG_DEBUG:
            printf("\033[1m");
            break;
        case LOG_NORMAL:
        default:
            //printf("\033[32m");
            break;
        }
    }
#endif

    va_list va;
    va_start(va, format);
    //printf("%s\t", category);
    vprintf(format, va);

#ifdef WIN32
    /* Restore original attributes */
    SetConsoleTextAttribute(hConsole, saved_attributes);
#else
    if(isatty(fileno(stdout))){
        printf("\033[0m");
    }
#endif

    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

void log_hex(int priority, const char *buf, int len, const char *format, ...)
{
    pthread_mutex_lock(&log_mutex);
    priority = priority;
#ifdef WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    WORD textAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    /* Save current attributes */
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(hConsole, textAttributes);
#else
    if(isatty(fileno(stdout))){
        if(isatty(fileno(stdout))){
            switch (priority) {
            case LOG_FATAL:
                printf("\033[37;41;1m");
                break;
            case LOG_ERROR:
                printf("\033[31m");
                break;
            case LOG_WARN:
                printf("\033[33m");
                break;
            case LOG_INFO:
                printf("\033[32;2m");
                break;
            case LOG_DEBUG:
                printf("\033[1m");
                break;
            case LOG_NORMAL:
            default:
                //printf("\033[32m");
                break;
            }
        }
    }
#endif

    va_list va;
    va_start(va, format);
    //printf("%s\t", category);
    vprintf(format, va);

    if( (format != NULL) && (0 != strlen(format)) ){
        printf(" ");
    }

    for(int i=0; i<len; i++){
        printf("%02x ", (unsigned char)buf[i]);
    }

#ifdef WIN32
    /* Restore original attributes */
    SetConsoleTextAttribute(hConsole, saved_attributes);
#else
    if(isatty(fileno(stdout))){
        printf("\033[0m");
    }
#endif

    printf("\n");

    pthread_mutex_unlock(&log_mutex);
}

void log_line(void)
{
    printf("\n\n--------------------------------------------------------------------------------\n");
}

void puthbuf(uint8_t *buf, int len)
{
    int i;
    for(i=0; i<len; i++){
        printf("%02X ", buf[i]);
    }
}

void putlen(int len)
{
    char buf[10];
    sprintf(buf, "<%d> ", len);
    printf("%6s", buf);
}
