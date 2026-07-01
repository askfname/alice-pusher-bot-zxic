#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <limits.h>
#include "../.build/avatar_asset.h"
#include "../.build/sponsor_asset.h"

#define MAX_BUFFER_LEN 4096
#define DEFAULT_WEBUI_PORT 51401
#define DEFAULT_CONFIG_PATH "/mnt/userdata/etc_rw/alice_pusher.conf"
#define DEFAULT_SERVICE_PID "/tmp/alice_pusher_service.pid"
#define DEFAULT_LOG_PATH "/tmp/alice_pusher.log"
#define DEFAULT_RUN_PATH "/mnt/userdata/alice-pusher-bot.run"
#define DEFAULT_BIN_PATH "/mnt/userdata/alice-pusher-bot"
#define DEFAULT_AUTOSTART_SCRIPT "/mnt/userdata/alice_pusher_autostart.sh"
#define DEFAULT_AUTOSTART_RC "/etc/rc"
#define AUTOSTART_BEGIN "# alice-pusher-bot autostart begin"
#define AUTOSTART_END "# alice-pusher-bot autostart end"
#define WEB_BODY_MAX 65536
#define WEB_REQ_MAX 16384
#define LOG_TAIL_MAX 32768
#define TARGET_MIFI_PATH "/sbin/zte_mifi"
#define TARGET_UFI_PATH "/sbin/zte_ufi"

static int g_webui_port = DEFAULT_WEBUI_PORT;
static volatile sig_atomic_t g_webui_restart_requested;
static int g_webui_restart_port;
static char g_target_path[256] = TARGET_MIFI_PATH;


// 函数声明
static pid_t get_strace_pid_from_file(void);
static void set_strace_pid_to_file(pid_t pid);
int send_webhook_msg(const char *webhook, const char *platform,
                     const char *txt, const char *custom_ctype,
                     const char *custom_body);
void print_mbedtls_error(int ret, const char *msg);
void parse_url(const char *url, char **host, char **path);
void signal_handler(int sig);
static int find_process_by_exe_path(const char *exe_path);
static void sigcont_process_by_path(const char *exe_path);
static int run_webui(const char *self_path, int port);
static void json_escape(char *out, size_t outsz, const char *in);
static void safe_copy(char *dst, size_t dstsz, const char *src);

// 线程控制变量
static volatile int threads_running = 1;
static pthread_t strace_thread_id;
static pthread_t pdu_thread_id;

static void process_strace_line_for_sms(const char *line, const char *webhook,
                                        const char *platform,
                                        const char *custom_ctype,
                                        const char *custom_body,
                                        const char *headtxt,
                                        const char *tailtxt);

typedef struct {
    char lines[256][MAX_BUFFER_LEN];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} strace_line_queue_t;

static strace_line_queue_t g_strace_queue = {
    .head = 0,
    .tail = 0,
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

static void strace_queue_push_line(const char *line) {
    pthread_mutex_lock(&g_strace_queue.mutex);
    if (g_strace_queue.count == (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]))) {
        g_strace_queue.head = (g_strace_queue.head + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
        g_strace_queue.count--;
    }
    strncpy(g_strace_queue.lines[g_strace_queue.tail], line, MAX_BUFFER_LEN - 1);
    g_strace_queue.lines[g_strace_queue.tail][MAX_BUFFER_LEN - 1] = 0;
    g_strace_queue.tail = (g_strace_queue.tail + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
    g_strace_queue.count++;
    pthread_cond_signal(&g_strace_queue.cond);
    pthread_mutex_unlock(&g_strace_queue.mutex);
}

static int strace_queue_pop_line(char *out, size_t outlen, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_strace_queue.mutex);
    while (threads_running && g_strace_queue.count == 0) {
        if (pthread_cond_timedwait(&g_strace_queue.cond, &g_strace_queue.mutex, &ts) == ETIMEDOUT) {
            pthread_mutex_unlock(&g_strace_queue.mutex);
            return 0;
        }
    }
    if (!threads_running || g_strace_queue.count == 0) {
        pthread_mutex_unlock(&g_strace_queue.mutex);
        return 0;
    }
    strncpy(out, g_strace_queue.lines[g_strace_queue.head], outlen - 1);
    out[outlen - 1] = 0;
    g_strace_queue.head = (g_strace_queue.head + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
    g_strace_queue.count--;
    pthread_mutex_unlock(&g_strace_queue.mutex);
    return 1;
}

static time_t get_next_midnight_epoch(void) {
    time_t now = time(NULL);
    struct tm *tm_now_ptr = localtime(&now);
    if (!tm_now_ptr) return now + 24 * 3600;
    struct tm tm_now = *tm_now_ptr;
    tm_now.tm_hour = 0;
    tm_now.tm_min = 0;
    tm_now.tm_sec = 0;
    time_t today_midnight = mktime(&tm_now);
    return today_midnight + 24 * 3600;
}

static int start_strace_with_pipe(int target_pid, pid_t *out_strace_pid, int *out_read_fd) {
    int fds[2];
    if (pipe(fds) != 0) return -1;

    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);

        char pidstr[16];
        snprintf(pidstr, sizeof(pidstr), "%d", target_pid);
        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr, (char*)NULL);
        _exit(127);
    }

    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    close(fds[1]);
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    }
    *out_strace_pid = child;
    *out_read_fd = fds[0];
    return 0;
}

// 用文件记录strace子进程pid，便于跨进程kill
static pid_t get_strace_pid_from_file() {
    FILE *fp = fopen("/tmp/zte_strace.pid", "r");
    if (!fp) return 0;
    pid_t pid = 0;
    fscanf(fp, "%d", &pid);
    fclose(fp);
    return pid;
}
static void set_strace_pid_to_file(pid_t pid) {
    FILE *fp = fopen("/tmp/zte_strace.pid", "w");
    if (fp) {
        fprintf(fp, "%d", pid);
        fclose(fp);
    }
}

// 查找指定可执行文件路径的进程 pid，返回第一个找到的 pid，找不到返回 -1
static int find_process_by_exe_path(const char *exe_path) {
    DIR *dir;
    struct dirent *entry;
    char path[256], buf[256];
    int pid = -1;
    if (!exe_path || !exe_path[0]) return -1;
    dir = opendir("/proc");
    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        int id = atoi(entry->d_name);
        if (id <= 0) continue;
        snprintf(path, sizeof(path), "/proc/%d/exe", id);
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            if (strcmp(buf, exe_path) == 0) {
                pid = id;
                break;
            }
        }
    }
    closedir(dir);
    return pid;
}

static void sigcont_process_by_path(const char *exe_path) {
    int pid = find_process_by_exe_path(exe_path);
    if (pid > 0)
        kill(pid, SIGCONT);
}

// strace线程函数 - 执行 strace 跟踪目标短信进程的 read/write 系统调用
void* strace_thread_func(void* arg) {
    const char *target_path = (const char *)arg;
    char local_target_path[256];

    if (!target_path || !target_path[0])
        target_path = TARGET_MIFI_PATH;
    safe_copy(local_target_path, sizeof(local_target_path), target_path);
    safe_copy(g_target_path, sizeof(g_target_path), local_target_path);
    target_path = local_target_path;

    while (threads_running) {
        int pid = find_process_by_exe_path(target_path);
        if (pid <= 0) {
            fprintf(stderr, "目标短信进程未找到: %s\n", target_path);
            sleep(1);
            continue;
        }

        pid_t strace_pid = 0;
        int read_fd = -1;
        if (start_strace_with_pipe(pid, &strace_pid, &read_fd) != 0) {
            perror("start_strace_with_pipe");
            sleep(1);
            continue;
        }
        set_strace_pid_to_file(strace_pid);
        time_t next_midnight = get_next_midnight_epoch();

        char partial[MAX_BUFFER_LEN];
        size_t partial_len = 0;
        while (threads_running) {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = read_fd;
            pfd.events = POLLIN;
            int pr = poll(&pfd, 1, 200);
            if (pr > 0 && (pfd.revents & POLLIN)) {
                char buf[2048];
                ssize_t n = read(read_fd, buf, sizeof(buf));
                if (n > 0) {
                    size_t i;
                    for (i = 0; i < (size_t)n; i++) {
                        char c = buf[i];
                        if (partial_len + 1 < sizeof(partial)) {
                            partial[partial_len++] = c;
                        }
                        if (c == '\n') {
                            partial[partial_len] = 0;
                            strace_queue_push_line(partial);
                            partial_len = 0;
                        }
                        if (partial_len + 1 >= sizeof(partial)) {
                            partial[partial_len] = 0;
                            strace_queue_push_line(partial);
                            partial_len = 0;
                        }
                    }
                } else if (n == 0) {
                    break;
                } else {
                    if (errno != EAGAIN && errno != EINTR) break;
                }
            }

            time_t now = time(NULL);
            if (now >= next_midnight) {
                kill(strace_pid, SIGTERM);
                int wait_count = 0;
                while (wait_count < 10) {
                    if (kill(strace_pid, 0) != 0) break;
                    usleep(100*1000);
                    wait_count++;
                }
                if (kill(strace_pid, 0) == 0) {
                    kill(strace_pid, SIGKILL);
                    usleep(200*1000);
                }
                sigcont_process_by_path(target_path);
                break;
            }

            int status = 0;
            pid_t w = waitpid(strace_pid, &status, WNOHANG);
            if (w == strace_pid) break;
        }

        close(read_fd);
        waitpid(strace_pid, NULL, 0);
        if (!threads_running) break;
        sleep(1);
    }
    return NULL;
}

// PDU处理线程函数
void* pdu_thread_func(void* arg) {
    char** args = (char**)arg;
    char* webhook = args[0];
    char* platform = args[1];
    char* custom_ctype = args[2];
    char* custom_body = args[3];
    char* headtxt = args[4];
    char* tailtxt = args[5];

    while (threads_running) {
        char line[MAX_BUFFER_LEN];
        if (strace_queue_pop_line(line, sizeof(line), 1000)) {
            process_strace_line_for_sms(line, webhook, platform,
                                        custom_ctype, custom_body,
                                        headtxt, tailtxt);
        }
    }
    return NULL;
}

// PDU解码信息结构体和解码函数

typedef struct {
    char smsc[32];
    char sender[32];
    char timestamp[32];
    char tp_pid[4];
    char tp_dcs[4];
    char tp_dcs_desc[32];
    char sms_class[8];
    char alphabet[32];
    char text[2048];
    int text_len;
} sms_info_t;

// 新增：基于Sender+TimeStamp+Text的去重队列
#define SMS_UNIQ_QUEUE_SIZE 100
typedef struct {
    char sender[32];
    char timestamp[32];
    char text[2048];
} sms_uniq_t;
static sms_uniq_t sms_uniq_queue[SMS_UNIQ_QUEUE_SIZE];
static int sms_uniq_head = 0;
static int sms_uniq_count = 0;

int is_sms_uniq_in_queue(const char *sender, const char *timestamp, const char *text) {
    int i;
    for (i = 0; i < sms_uniq_count; i++) {
        int idx = (sms_uniq_head + i) % SMS_UNIQ_QUEUE_SIZE;
        if (strcmp(sms_uniq_queue[idx].sender, sender) == 0 &&
            strcmp(sms_uniq_queue[idx].timestamp, timestamp) == 0 &&
            strcmp(sms_uniq_queue[idx].text, text) == 0) {
            return 1;
        }
    }
    return 0;
}
void add_sms_uniq_to_queue(const char *sender, const char *timestamp, const char *text) {
    int idx;
    if (sms_uniq_count < SMS_UNIQ_QUEUE_SIZE) {
        idx = (sms_uniq_head + sms_uniq_count) % SMS_UNIQ_QUEUE_SIZE;
        strncpy(sms_uniq_queue[idx].sender, sender, sizeof(sms_uniq_queue[idx].sender)-1);
        sms_uniq_queue[idx].sender[sizeof(sms_uniq_queue[idx].sender)-1] = 0;
        strncpy(sms_uniq_queue[idx].timestamp, timestamp, sizeof(sms_uniq_queue[idx].timestamp)-1);
        sms_uniq_queue[idx].timestamp[sizeof(sms_uniq_queue[idx].timestamp)-1] = 0;
        strncpy(sms_uniq_queue[idx].text, text, sizeof(sms_uniq_queue[idx].text)-1);
        sms_uniq_queue[idx].text[sizeof(sms_uniq_queue[idx].text)-1] = 0;
        sms_uniq_count++;
    } else {
        strncpy(sms_uniq_queue[sms_uniq_head].sender, sender, sizeof(sms_uniq_queue[0].sender)-1);
        sms_uniq_queue[sms_uniq_head].sender[sizeof(sms_uniq_queue[0].sender)-1] = 0;
        strncpy(sms_uniq_queue[sms_uniq_head].timestamp, timestamp, sizeof(sms_uniq_queue[0].timestamp)-1);
        sms_uniq_queue[sms_uniq_head].timestamp[sizeof(sms_uniq_queue[0].timestamp)-1] = 0;
        strncpy(sms_uniq_queue[sms_uniq_head].text, text, sizeof(sms_uniq_queue[0].text)-1);
        sms_uniq_queue[sms_uniq_head].text[sizeof(sms_uniq_queue[0].text)-1] = 0;
        sms_uniq_head = (sms_uniq_head + 1) % SMS_UNIQ_QUEUE_SIZE;
    }
}

static char device_msisdn[64] = "";

static void load_device_msisdn_from_nv_show(void) {
    device_msisdn[0] = 0;
    FILE *fp = popen("nv show", "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "msisdn=");
        if (!p) continue;
        p += strlen("msisdn=");
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '"' || *p == '\'') p++;
        char *end = p;
        while (*end && !isspace((unsigned char)*end) && *end != '"' && *end != '\'' && *end != ';') end++;
        size_t len = (size_t)(end - p);
        if (len == 0) continue;
        if (len >= sizeof(device_msisdn)) len = sizeof(device_msisdn) - 1;
        memcpy(device_msisdn, p, len);
        device_msisdn[len] = 0;
        break;
    }

    pclose(fp);
}

// 完整的PDU解码，包含SMSC、发件人、时间戳等信息
void decode_pdu(const char *pdu, sms_info_t *info) {
    memset(info, 0, sizeof(*info));
    int idx = 0;
    int smsc_len = 0;
    int i, j, k; // 统一声明循环变量
    sscanf(pdu, "%2x", &smsc_len);
    idx += 2;
    int smsc_type = 0;
    sscanf(pdu + idx, "%2x", &smsc_type);
    idx += 2;
    int smsc_bcd_len = (smsc_len - 1) * 2;
    char smsc_bcd[32] = {0};
    strncpy(smsc_bcd, pdu + idx, smsc_bcd_len);
    smsc_bcd[smsc_bcd_len] = 0;
    idx += smsc_bcd_len;
    j = 0;
    for (i = 0; i < smsc_bcd_len; i += 2) {
        if (smsc_bcd[i+1] == 'F' || smsc_bcd[i+1] == 'f') {
            info->smsc[j++] = smsc_bcd[i];
        } else {
            info->smsc[j++] = smsc_bcd[i+1];
            info->smsc[j++] = smsc_bcd[i];
        }
    }
    info->smsc[j] = 0;
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->smsc, "86", 2) == 0) {
        memmove(info->smsc, info->smsc + 2, strlen(info->smsc + 2) + 1);
    }

    int first_octet = 0;
    sscanf(pdu + idx, "%2x", &first_octet);
    idx += 2;
    int sender_len = 0;
    sscanf(pdu + idx, "%2x", &sender_len);
    idx += 2;
    int sender_type = 0;
    sscanf(pdu + idx, "%2x", &sender_type);
    idx += 2;
    int sender_bcd_len = (sender_len % 2 == 0) ? sender_len : sender_len + 1;
    sender_bcd_len /= 2;
    sender_bcd_len *= 2;
    char sender_bcd[32] = {0};
    strncpy(sender_bcd, pdu + idx, sender_bcd_len);
    sender_bcd[sender_bcd_len] = 0;
    idx += sender_bcd_len;
    j = 0;
    for (i = 0; i < sender_bcd_len; i += 2) {
        if (sender_bcd[i+1] == 'F' || sender_bcd[i+1] == 'f') {
            info->sender[j++] = sender_bcd[i];
        } else {
            info->sender[j++] = sender_bcd[i+1];
            info->sender[j++] = sender_bcd[i];
        }
    }
    info->sender[j] = 0;
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->sender, "86", 2) == 0) {
        memmove(info->sender, info->sender + 2, strlen(info->sender + 2) + 1);
    }

    // TP_PID
    strncpy(info->tp_pid, pdu + idx, 2);
    info->tp_pid[2] = 0;
    idx += 2;

    // TP_DCS
    strncpy(info->tp_dcs, pdu + idx, 2);
    info->tp_dcs[2] = 0;
    idx += 2;
    if (strcmp(info->tp_dcs, "08") == 0) {
        strcpy(info->tp_dcs_desc, "Uncompressed Text");
        strcpy(info->sms_class, "0");
        strcpy(info->alphabet, "UCS2(16)bit");
    } else {
        strcpy(info->tp_dcs_desc, "Unknown");
        strcpy(info->sms_class, "?");
        strcpy(info->alphabet, "Unknown");
    }

    // 时间戳
    char ts[15] = {0};
    strncpy(ts, pdu + idx, 14);
    ts[14] = 0;
    idx += 14;
    char dt[32] = {0};
    for (i = 0; i < 12; i += 2) {
        dt[i] = ts[i+1];
        dt[i+1] = ts[i];
    }
    snprintf(info->timestamp, sizeof(info->timestamp), "%c%c/%c%c/%c%c %c%c:%c%c:%c%c",
        dt[0], dt[1], dt[2], dt[3], dt[4], dt[5], dt[6], dt[7], dt[8], dt[9], dt[10], dt[11]);

    int text_len_oct = 0;
    sscanf(pdu + idx, "%2x", &text_len_oct);
    idx += 2;
    info->text_len = text_len_oct;

    size_t pdu_total_len = strlen(pdu);
    size_t remaining = pdu_total_len > (size_t)idx ? (pdu_total_len - (size_t)idx) : 0;
    size_t expected_ud_hex_len = (size_t)text_len_oct * 2;
    size_t ud_hex_len = expected_ud_hex_len;
    if (ud_hex_len > remaining) ud_hex_len = remaining;

    size_t ud_start_offset = 0;
    if ((first_octet & 0x40) && ud_hex_len >= 2) {
        unsigned int udhl = 0;
        if (sscanf(pdu + idx, "%2x", &udhl) == 1) {
            size_t header_hex = ((size_t)udhl + 1) * 2;
            if (header_hex < ud_hex_len) {
                ud_start_offset = header_hex;
            }
        }
    }

    const char *ud_hex_ptr = pdu + idx + (int)ud_start_offset;
    size_t ud_hex_len_after = ud_hex_len > ud_start_offset ? (ud_hex_len - ud_start_offset) : 0;
    char *ucs2_hex = (char*)malloc(ud_hex_len_after + 1);
    if (!ucs2_hex) {
        info->text[0] = 0;
        return;
    }
    memcpy(ucs2_hex, ud_hex_ptr, ud_hex_len_after);
    ucs2_hex[ud_hex_len_after] = 0;
    k = 0;
    for (i = 0; i + 3 < (int)ud_hex_len_after && k + 3 < (int)sizeof(info->text); i += 4) {
        unsigned int ucs2;
        if (sscanf(ucs2_hex + i, "%4x", &ucs2) != 1) break;
        if (ucs2 < 0x80) {
            info->text[k++] = (char)ucs2;
        } else if (ucs2 < 0x800) {
            info->text[k++] = 0xC0 | (ucs2 >> 6);
            info->text[k++] = 0x80 | (ucs2 & 0x3F);
        } else {
            info->text[k++] = 0xE0 | (ucs2 >> 12);
            info->text[k++] = 0x80 | ((ucs2 >> 6) & 0x3F);
            info->text[k++] = 0x80 | (ucs2 & 0x3F);
        }
    }
    info->text[k] = 0;
    free(ucs2_hex);
}

static void form_url_escape(char *out, size_t outsz, const char *in) {
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out[used++] = (char)c;
        } else if (used + 3 < outsz) {
            out[used++] = '%';
            out[used++] = hex[c >> 4];
            out[used++] = hex[c & 0x0f];
        } else {
            break;
        }
    }
    out[used] = 0;
}

static int replace_token(char *out, size_t outsz, const char *token,
                         const char *value) {
    size_t tlen = strlen(token);
    size_t vlen = strlen(value ? value : "");
    char *p = strstr(out, token);
    size_t tail_len;

    while (p) {
        tail_len = strlen(p + tlen);
        if ((size_t)(p - out) + vlen + tail_len >= outsz)
            return -1;
        memmove(p + vlen, p + tlen, tail_len + 1);
        memcpy(p, value ? value : "", vlen);
        p = strstr(p + vlen, token);
    }
    return 0;
}

static int render_custom_body(const char *tmpl, const char *txt,
                              char *out, size_t outsz) {
    char json_txt[3072];
    char url_txt[3072];

    if (!tmpl || !tmpl[0] || !outsz)
        return -1;
    safe_copy(out, outsz, tmpl);
    json_escape(json_txt, sizeof(json_txt), txt);
    form_url_escape(url_txt, sizeof(url_txt), txt);
    if (replace_token(out, outsz, "{{json_text}}", json_txt) < 0)
        return -1;
    if (replace_token(out, outsz, "{{url_text}}", url_txt) < 0)
        return -1;
    if (replace_token(out, outsz, "{{text}}", txt ? txt : "") < 0)
        return -1;
    return 0;
}

static int extract_bark_device_key(const char *url, char *out, size_t outsz) {
    const char *p;
    const char *end;
    size_t len;

    if (!url || !out || outsz == 0)
        return -1;
    out[0] = 0;
    p = strstr(url, "://");
    p = p ? p + 3 : url;
    p = strchr(p, '/');
    if (!p || !p[1])
        return -1;
    p++;
    if (strncmp(p, "push", 4) == 0 &&
        (p[4] == 0 || p[4] == '?' || p[4] == '/' || p[4] == '#'))
        return -1;
    end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#')
        end++;
    len = (size_t)(end - p);
    if (len == 0 || len >= outsz)
        return -1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

static int build_webhook_payload(const char *webhook, const char *platform,
                                 const char *txt,
                                 const char *custom_ctype,
                                 const char *custom_body,
                                 char *payload, size_t payload_sz,
                                 char *ctype, size_t ctype_sz) {
    char safe_txt[3072];
    char safe_key[512];
    char enc_txt[3072];
    const char *p = platform && platform[0] ? platform : "dingtalk";

    if (!payload_sz || !ctype_sz)
        return -1;
    payload[0] = 0;
    ctype[0] = 0;

    if (strcmp(p, "serverchan") == 0) {
        form_url_escape(enc_txt, sizeof(enc_txt), txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "title=Alice%%20Pusher&desp=%s", enc_txt);
        return payload[0] ? 0 : -1;
    }
    if (strcmp(p, "telegram") == 0) {
        form_url_escape(enc_txt, sizeof(enc_txt), txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "text=%s", enc_txt);
        return payload[0] ? 0 : -1;
    }
    if (strcmp(p, "custom") == 0) {
        const char *tmpl = custom_body && custom_body[0] ? custom_body :
                           "{\"text\":\"{{json_text}}\"}";
        snprintf(ctype, ctype_sz, "%s",
                 custom_ctype && custom_ctype[0] ? custom_ctype :
                 "application/json;charset=utf-8");
        if (render_custom_body(tmpl, txt, payload, payload_sz) < 0)
            return -1;
        return payload[0] ? 0 : -1;
    }

    json_escape(safe_txt, sizeof(safe_txt), txt);
    snprintf(ctype, ctype_sz, "application/json;charset=utf-8");
    if (strcmp(p, "feishu") == 0) {
        snprintf(payload, payload_sz,
                 "{\"msg_type\":\"text\",\"content\":{\"text\":\"%s\"}}",
                 safe_txt);
    } else if (strcmp(p, "discord") == 0) {
        snprintf(payload, payload_sz,
                 "{\"content\":\"%s\"}",
                 safe_txt);
    } else if (strcmp(p, "bark") == 0) {
        char bark_key[256];
        if (extract_bark_device_key(webhook, bark_key, sizeof(bark_key)) < 0)
            return -1;
        json_escape(safe_key, sizeof(safe_key), bark_key);
        snprintf(payload, payload_sz,
                 "{\"title\":\"Alice Pusher\",\"body\":\"%s\",\"device_key\":\"%s\"}",
                 safe_txt, safe_key);
    } else {
        snprintf(payload, payload_sz,
                 "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}",
                 safe_txt);
    }
    return payload[0] ? 0 : -1;
}

static int post_https_body(const char *webhook, const char *ctype,
                           const char *payload, const char *platform) {
    char *host = NULL, *path = NULL;
    const char *request_path;
    char request_buffer[8192];
    unsigned char read_buf[1024];
    int request_len;
    int ret = 0;
    int rc = -1;
    const char *port = "443";
    const char *pers = "ssl_client";
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    parse_url(webhook, &host, &path);
    if (!host || !path) {
        fprintf(stderr, "[WEBHOOK] invalid url\n");
        goto cleanup_strings;
    }
    request_path = path;
    if (platform && strcmp(platform, "bark") == 0)
        request_path = "/push";

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                     &entropy, (const unsigned char *)pers,
                                     strlen(pers))) != 0) {
        print_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
        goto cleanup_tls;
    }
    if ((ret = mbedtls_net_connect(&server_fd, host, port,
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_mbedtls_error(ret, "mbedtls_net_connect");
        goto cleanup_tls;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto cleanup_tls;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto cleanup_tls;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                        mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_handshake");
            goto cleanup_tls;
        }
    }

    request_len = snprintf(request_buffer, sizeof(request_buffer),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: alice-pusher-bot/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        request_path, host, ctype, strlen(payload), payload);
    if (request_len <= 0 || request_len >= (int)sizeof(request_buffer)) {
        fprintf(stderr, "[WEBHOOK] request too large\n");
        goto cleanup_tls;
    }

    printf("[WEBHOOK] platform=%s host=%s bytes=%zu\n",
           platform ? platform : "dingtalk", host, strlen(payload));
    while ((ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)request_buffer,
                                    (size_t)request_len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_write");
            goto cleanup_tls;
        }
    }

    memset(read_buf, 0, sizeof(read_buf));
    ret = mbedtls_ssl_read(&ssl, read_buf, sizeof(read_buf) - 1);
    if (ret > 0)
        printf("[WEBHOOK] response: %s\n", read_buf);
    else if (ret < 0 &&
             ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY &&
             ret != MBEDTLS_ERR_SSL_WANT_READ)
        print_mbedtls_error(ret, "mbedtls_ssl_read");
    rc = 0;

cleanup_tls:
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
cleanup_strings:
    if (host) free(host);
    if (path) free(path);
    return rc;
}

int send_webhook_msg(const char *webhook, const char *platform,
                     const char *txt, const char *custom_ctype,
                     const char *custom_body) {
    char payload[4096];
    char ctype[160];
    const char *p = platform && platform[0] ? platform : "dingtalk";

    if (!webhook || !webhook[0] || !txt)
        return -1;
    if (build_webhook_payload(webhook, p, txt, custom_ctype, custom_body,
                              payload, sizeof(payload),
                              ctype, sizeof(ctype)) < 0)
        return -1;
    return post_https_body(webhook, ctype, payload, p);
}

static void append_message_text(char *out, size_t outsz, const char *text) {
    size_t used;
    size_t left;

    if (!out || outsz == 0 || !text || !text[0])
        return;
    used = strlen(out);
    if (used >= outsz - 1)
        return;
    left = outsz - used - 1;
    strncat(out, text, left);
}

static void build_push_message(char *out, size_t outsz,
                               const char *headtxt,
                               const char *body,
                               const char *tailtxt) {
    if (!out || outsz == 0)
        return;
    out[0] = 0;
    if (headtxt && headtxt[0]) {
        append_message_text(out, outsz, headtxt);
        append_message_text(out, outsz, "\n");
    }
    append_message_text(out, outsz, body);
    if (tailtxt && tailtxt[0]) {
        if (out[0])
            append_message_text(out, outsz, "\n");
        append_message_text(out, outsz, tailtxt);
    }
}

static void process_strace_line_for_sms(const char *line, const char *webhook,
                                        const char *platform,
                                        const char *custom_ctype,
                                        const char *custom_body,
                                        const char *headtxt,
                                        const char *tailtxt) {
    char local[MAX_BUFFER_LEN];
    strncpy(local, line, sizeof(local) - 1);
    local[sizeof(local) - 1] = 0;

    char *p = strstr(local, "+CMT: ");
    if (p) {
        char *first_crlf = strstr(p, "\\r\\n");
        if (first_crlf) {
            char *pdu_start = first_crlf + 4;
            char *pdu_end = strstr(pdu_start, "\\r\\n");
            char pdu[2048] = "";
            if (pdu_end && pdu_end > pdu_start && (pdu_end - pdu_start) < (int)sizeof(pdu)) {
                strncpy(pdu, pdu_start, pdu_end - pdu_start);
                pdu[pdu_end - pdu_start] = 0;
            } else {
                strncpy(pdu, pdu_start, sizeof(pdu)-1);
                pdu[sizeof(pdu)-1] = 0;
            }
            char *pdubegin = pdu;
            while (*pdubegin && (*pdubegin == ' ' || *pdubegin == '\t')) pdubegin++;
            char *pdu_trim = pdubegin;
            size_t trim_len = strlen(pdu_trim);
            if (trim_len > 0) {
                char *pdutail = pdu_trim + trim_len - 1;
                while (pdutail > pdu_trim && (*pdutail == ' ' || *pdutail == '\t')) {
                    *pdutail-- = 0;
                }
            }
            if (pdu_trim[0]) {
                int valid_pdu = 1;
                size_t pdu_len = strlen(pdu_trim);
                size_t pi;
                if (pdu_len < 20) valid_pdu = 0;
                for (pi = 0; pi < pdu_len; pi++) {
                    char c = pdu_trim[pi];
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                        valid_pdu = 0;
                        break;
                    }
                }
                if (valid_pdu) {
                    sms_info_t info;
                    decode_pdu(pdu_trim, &info);
                    size_t textlen = strlen(info.text);
                    if (textlen > 0) {
                        if (!is_sms_uniq_in_queue(info.sender, info.timestamp, info.text)) {
                            add_sms_uniq_to_queue(info.sender, info.timestamp, info.text);
                            char msg[1024];
                            char final_msg[2048];
                            snprintf(msg, sizeof(msg),
                                "接收短信设备手机号:%s\n[pdu解码后的信息]\n短消息服务中心:%s\n发件人:%s\n时间戳:%s\n短信内容:%s",
                                device_msisdn[0] ? device_msisdn : "N/A",
                                info.smsc[0] ? info.smsc : "N/A",
                                info.sender[0] ? info.sender : "N/A",
                                info.timestamp[0] ? info.timestamp : "N/A",
                                info.text);
                            build_push_message(final_msg, sizeof(final_msg),
                                               headtxt, msg, tailtxt);
                            send_webhook_msg(webhook, platform, final_msg,
                                             custom_ctype, custom_body);
                        }
                    }
                }
            }
        }
    }
}

// 打印 mbedtls 错误码的帮助函数
void print_mbedtls_error(int ret, const char *msg) {
    fprintf(stderr, "%s failed: -0x%x\n", msg, -ret);
}

// 从 URL 中提取主机名和路径
void parse_url(const char *url, char **host, char **path) {
    char *start;
    char *end;

    if (strstr(url, "https://") == url) {
        start = (char *)url + strlen("https://");
    } else {
        *host = NULL;
        *path = NULL;
        return;
    }

    end = strchr(start, '/');
    if (end) {
        *host = (char *)malloc(end - start + 1);
        strncpy(*host, start, end - start);
        (*host)[end - start] = '\0';
        *path = strdup(end);
    } else {
        *host = strdup(start);
        *path = strdup("/");
    }
}

// 信号处理函数，用于优雅关闭线程
void signal_handler(int sig) {
    (void)sig;
    threads_running = 0;
    
    // 给线程一些时间来清理
    sleep(1);
    
    // 强制杀死strace进程
    pid_t strace_pid = get_strace_pid_from_file();
    if (strace_pid > 0) {
        kill(strace_pid, SIGTERM);
        usleep(100*1000);
        if (kill(strace_pid, 0) == 0) {
            kill(strace_pid, SIGKILL);
        }
    }
    sigcont_process_by_path(g_target_path);
    sigcont_process_by_path(TARGET_MIFI_PATH);
    sigcont_process_by_path(TARGET_UFI_PATH);
    
    exit(0);
}

typedef struct {
    char webhook[1024];
    char platform[32];
    char target_mode[32];
    char target_path[256];
    char custom_ctype[128];
    char custom_body[2048];
    char num[128];
    char headtxt[256];
    char tailtxt[256];
    int port;
} web_config_t;

typedef struct {
    int run_ready;
    int bin_ready;
    int script_ready;
    int hook_ready;
} autostart_status_t;

static void safe_copy(char *dst, size_t dstsz, const char *src) {
    if (!dstsz) return;
    if (!src) src = "";
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = 0;
}

static const char *normalize_platform(const char *platform) {
    if (!platform || !platform[0]) return "dingtalk";
    if (strcmp(platform, "dingtalk") == 0) return "dingtalk";
    if (strcmp(platform, "feishu") == 0) return "feishu";
    if (strcmp(platform, "wecom") == 0) return "wecom";
    if (strcmp(platform, "serverchan") == 0) return "serverchan";
    if (strcmp(platform, "discord") == 0) return "discord";
    if (strcmp(platform, "telegram") == 0) return "telegram";
    if (strcmp(platform, "bark") == 0) return "bark";
    if (strcmp(platform, "custom") == 0) return "custom";
    return "dingtalk";
}

static const char *platform_label(const char *platform) {
    platform = normalize_platform(platform);
    if (strcmp(platform, "feishu") == 0) return "飞书";
    if (strcmp(platform, "wecom") == 0) return "企业微信";
    if (strcmp(platform, "serverchan") == 0) return "Server 酱";
    if (strcmp(platform, "discord") == 0) return "Discord";
    if (strcmp(platform, "telegram") == 0) return "Telegram Bot";
    if (strcmp(platform, "bark") == 0) return "Bark";
    if (strcmp(platform, "custom") == 0) return "自定义";
    return "钉钉";
}

static const char *normalize_target_mode(const char *mode) {
    if (!mode || !mode[0]) return "mifi";
    if (strcmp(mode, "mifi") == 0) return "mifi";
    if (strcmp(mode, "ufi") == 0) return "ufi";
    if (strcmp(mode, "custom") == 0) return "custom";
    return "mifi";
}

static const char *target_mode_label(const char *mode) {
    mode = normalize_target_mode(mode);
    if (strcmp(mode, "ufi") == 0) return "ZTE UFI";
    if (strcmp(mode, "custom") == 0) return "自定义";
    return "ZTE MiFi";
}

static const char *target_default_path(const char *mode) {
    mode = normalize_target_mode(mode);
    if (strcmp(mode, "ufi") == 0) return TARGET_UFI_PATH;
    return TARGET_MIFI_PATH;
}

static const char *target_selected_attr(const char *mode, const char *value) {
    return strcmp(normalize_target_mode(mode), value) == 0 ? " selected" : "";
}

static void resolve_target_path(const web_config_t *cfg, char *out, size_t outsz) {
    const char *mode = cfg ? normalize_target_mode(cfg->target_mode) : "mifi";

    if (!outsz) return;
    if (strcmp(mode, "custom") == 0 && cfg && cfg->target_path[0])
        safe_copy(out, outsz, cfg->target_path);
    else
        safe_copy(out, outsz, target_default_path(mode));
    if (!out[0])
        safe_copy(out, outsz, TARGET_MIFI_PATH);
}

static const char *detect_platform_from_url(const char *url) {
    if (!url) return "dingtalk";
    if (strstr(url, "open.feishu.cn") || strstr(url, "feishu.cn/"))
        return "feishu";
    if (strstr(url, "qyapi.weixin.qq.com") ||
        strstr(url, "work.weixin.qq.com"))
        return "wecom";
    if (strstr(url, "sctapi.ftqq.com") || strstr(url, "sc.ftqq.com"))
        return "serverchan";
    if (strstr(url, "discord.com/api/webhooks/") ||
        strstr(url, "discordapp.com/api/webhooks/"))
        return "discord";
    if (strstr(url, "api.telegram.org/bot"))
        return "telegram";
    if (strstr(url, "api.day.app"))
        return "bark";
    return "dingtalk";
}

static const char *selected_attr(const char *platform, const char *value) {
    return strcmp(normalize_platform(platform), value) == 0 ? " selected" : "";
}

static void strip_line(char *s) {
    size_t len;
    if (!s) return;
    len = strlen(s);
    while (len && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = 0;
    }
}

static void remove_newlines(char *s) {
    while (s && *s) {
        if (*s == '\r' || *s == '\n')
            *s = ' ';
        s++;
    }
}

static void config_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if (c == '\\' || c == '\n' || c == '\r') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = c == '\n' ? 'n' : (c == '\r' ? 'r' : '\\');
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = 0;
}

static void config_unescape(char *out, size_t outsz, const char *in) {
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        char c = *in++;
        if (c == '\\' && *in) {
            char n = *in++;
            if (n == 'n') c = '\n';
            else if (n == 'r') c = '\r';
            else if (n == '\\') c = '\\';
            else {
                if (used + 2 >= outsz) break;
                out[used++] = '\\';
                c = n;
            }
        }
        out[used++] = c;
    }
    out[used] = 0;
}

static int mkdir_p(const char *path) {
    char tmp[512];
    char *p;

    safe_copy(tmp, sizeof(tmp), path);
    if (!tmp[0]) return -1;
    for (p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        mkdir(tmp, 0755);
        *p = '/';
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int mkdir_parent_file(const char *path) {
    char tmp[512];
    char *slash;

    safe_copy(tmp, sizeof(tmp), path);
    slash = strrchr(tmp, '/');
    if (!slash) return 0;
    *slash = 0;
    if (!tmp[0]) return 0;
    return mkdir_p(tmp);
}

static char *read_file_alloc(const char *path, size_t max_size, size_t *len_out) {
    struct stat st;
    char *buf;
    int fd;
    size_t off = 0;

    if (stat(path, &st) < 0 || st.st_size < 0 ||
        (size_t)st.st_size > max_size)
        return NULL;
    buf = (char *)malloc((size_t)st.st_size + 1);
    if (!buf)
        return NULL;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(buf);
        return NULL;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    buf[off] = 0;
    if (len_out) *len_out = off;
    return buf;
}

static int file_contains(const char *path, const char *needle) {
    char *buf = read_file_alloc(path, 128 * 1024, NULL);
    int found;

    if (!buf) return 0;
    found = strstr(buf, needle) != NULL;
    free(buf);
    return found;
}

static void shell_quote(FILE *fp, const char *s) {
    fputc('\'', fp);
    for (; s && *s; s++) {
        if (*s == '\'')
            fputs("'\\''", fp);
        else
            fputc(*s, fp);
    }
    fputc('\'', fp);
}

static int write_all_fd(int fd, const char *buf, size_t len) {
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int path_is_regular_readable(const char *path) {
    struct stat st;

    if (!path || !path[0]) {
        errno = EINVAL;
        return 0;
    }
    if (stat(path, &st) < 0)
        return 0;
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return 0;
    }
    return access(path, R_OK) == 0;
}

static int path_is_same_file(const char *a, const char *b) {
    struct stat sa, sb;

    if (!a || !b || stat(a, &sa) < 0 || stat(b, &sb) < 0)
        return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static int copy_regular_file(const char *src, const char *dst, mode_t mode) {
    unsigned char buf[16384];
    char tmp[PATH_MAX];
    struct stat st;
    ssize_t n;
    int in = -1;
    int out = -1;
    int saved_errno;
    int rc = -1;

    if (!path_is_regular_readable(src))
        return -1;
    if (stat(src, &st) < 0 || !S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (path_is_same_file(src, dst))
        return chmod(dst, mode);
    if (mkdir_parent_file(dst) < 0)
        return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst, (long)getpid()) >=
        (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    in = open(src, O_RDONLY);
    if (in < 0) goto out;
    out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) goto out;
    for (;;) {
        n = read(in, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            goto out;
        }
        if (n == 0) break;
        if (write_all_fd(out, (const char *)buf, (size_t)n) < 0)
            goto out;
    }
    if (fsync(out) < 0) goto out;
    if (close(out) < 0) {
        out = -1;
        goto out;
    }
    out = -1;
    if (chmod(tmp, mode) < 0) goto out;
    if (rename(tmp, dst) < 0) goto out;
    rc = 0;

out:
    saved_errno = errno;
    if (out >= 0) close(out);
    if (in >= 0) close(in);
    if (rc < 0) unlink(tmp);
    errno = saved_errno;
    return rc;
}

static int current_exe_path(char *out, size_t outsz) {
    ssize_t n;

    if (!out || outsz == 0) {
        errno = EINVAL;
        return -1;
    }
    n = readlink("/proc/self/exe", out, outsz - 1);
    if (n < 0)
        return -1;
    out[n] = 0;
    return 0;
}

static void get_autostart_status(autostart_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->run_ready = access(DEFAULT_RUN_PATH, R_OK) == 0;
    st->bin_ready = access(DEFAULT_BIN_PATH, X_OK) == 0;
    st->script_ready = access(DEFAULT_AUTOSTART_SCRIPT, R_OK) == 0;
    st->hook_ready = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN) &&
                     file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_END);
}

static void remount_userdata_rw(void) {
    system("mount -o remount,rw,exec /mnt/userdata 2>/dev/null || "
           "mount -o remount,rw /mnt/userdata 2>/dev/null");
}

static void remount_root_rw(void) {
    system("mount -o remount,rw / 2>/dev/null; "
           "mount -o remount,rw /dev/root / 2>/dev/null");
}

static void remount_root_ro(void) {
    system("sync; mount -o remount,ro / 2>/dev/null; "
           "mount -o remount,ro /dev/root / 2>/dev/null");
}

static int install_autostart_payload(int *payload_kind) {
    const char *run_src;
    char exe[PATH_MAX];
    int run_errno = 0;

    if (payload_kind) *payload_kind = 0;
    remount_userdata_rw();

    run_src = getenv("ALICE_PUSHER_RUN_SOURCE");
    if (path_is_regular_readable(run_src)) {
        if (copy_regular_file(run_src, DEFAULT_RUN_PATH, 0755) == 0) {
            if (payload_kind) *payload_kind = 1;
            sync();
            return 0;
        }
        run_errno = errno;
    }

    if (current_exe_path(exe, sizeof(exe)) == 0 &&
        path_is_regular_readable(exe)) {
        if (copy_regular_file(exe, DEFAULT_BIN_PATH, 0755) == 0) {
            if (payload_kind) *payload_kind = 2;
            sync();
            return 0;
        }
    }

    if (run_errno)
        errno = run_errno;
    return -1;
}

static void write_autostart_exec_block(FILE *fp, const char *var,
                                       int use_shell) {
    fprintf(fp, "if [ %s \"$%s\" ]; then\n", use_shell ? "-r" : "-x", var);
    fprintf(fp, "\texec ");
    if (use_shell)
        fprintf(fp, "/bin/sh ");
    fprintf(fp, "\"$%s\" -w\n", var);
    fprintf(fp, "fi\n");
}

static int write_autostart_script(void) {
    int fd;
    int payload_kind = 0;
    FILE *fp;

    if (install_autostart_payload(&payload_kind) < 0)
        return -1;
    if (mkdir_parent_file(DEFAULT_AUTOSTART_SCRIPT) < 0)
        return -1;
    fd = open(DEFAULT_AUTOSTART_SCRIPT,
              O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        return -1;
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }

    fprintf(fp, "#!/bin/sh\n");
    fprintf(fp, "# generated by alice-pusher-bot\n");
    fprintf(fp, "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n");
    fprintf(fp, "mount -o remount,exec /tmp 2>/dev/null || true\n");
    fprintf(fp, "mount -o remount,rw,exec /mnt/userdata 2>/dev/null || mount -o remount,rw /mnt/userdata 2>/dev/null || true\n");
    fprintf(fp, "RUN=");
    shell_quote(fp, DEFAULT_RUN_PATH);
    fprintf(fp, "\nBIN=");
    shell_quote(fp, DEFAULT_BIN_PATH);
    fprintf(fp, "\n");
    if (payload_kind == 2) {
        write_autostart_exec_block(fp, "BIN", 0);
        write_autostart_exec_block(fp, "RUN", 1);
    } else {
        write_autostart_exec_block(fp, "RUN", 1);
        write_autostart_exec_block(fp, "BIN", 0);
    }
    fprintf(fp, "echo \"missing alice-pusher-bot startup payload\" >&2\n");
    fprintf(fp, "exit 127\n");
    if (fclose(fp) != 0)
        return -1;
    return chmod(DEFAULT_AUTOSTART_SCRIPT, 0755);
}

static int install_autostart_hook(void) {
    FILE *fp;
    int has_begin = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN);
    int has_end = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_END);

    if (has_begin && has_end)
        return 0;
    if (has_begin || has_end) {
        errno = EINVAL;
        return -1;
    }

    remount_root_rw();
    fp = fopen(DEFAULT_AUTOSTART_RC, "a");
    if (!fp) {
        remount_root_ro();
        return -1;
    }
    fprintf(fp, "\n%s\n", AUTOSTART_BEGIN);
    fprintf(fp, "if [ -f %s ]; then\n", DEFAULT_AUTOSTART_SCRIPT);
    fprintf(fp, "\t/bin/sh %s >/tmp/alice_pusher_autostart.out 2>/tmp/alice_pusher_autostart.err &\n",
            DEFAULT_AUTOSTART_SCRIPT);
    fprintf(fp, "fi\n");
    fprintf(fp, "%s\n", AUTOSTART_END);
    if (fclose(fp) != 0) {
        remount_root_ro();
        return -1;
    }
    sync();
    remount_root_ro();
    return 0;
}

static int remove_autostart_hook(void) {
    char *buf;
    char *begin;
    char *end;
    char tmp_path[] = DEFAULT_AUTOSTART_RC ".alice_pusher_tmp";
    struct stat st;
    size_t len;
    int fd;
    int rc = -1;

    buf = read_file_alloc(DEFAULT_AUTOSTART_RC, 128 * 1024, &len);
    if (!buf)
        return file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN) ? -1 : 0;
    begin = strstr(buf, AUTOSTART_BEGIN);
    if (!begin) {
        free(buf);
        return 0;
    }
    end = strstr(begin, AUTOSTART_END);
    if (!end) {
        free(buf);
        errno = EINVAL;
        return -1;
    }
    if (begin > buf && begin[-1] == '\n')
        begin--;
    end += strlen(AUTOSTART_END);
    if (*end == '\r') end++;
    if (*end == '\n') end++;

    remount_root_rw();
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0744);
    if (fd < 0) goto out;
    if (write_all_fd(fd, buf, (size_t)(begin - buf)) < 0) goto out_close;
    if (write_all_fd(fd, end, len - (size_t)(end - buf)) < 0) goto out_close;
    if (close(fd) < 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (stat(DEFAULT_AUTOSTART_RC, &st) == 0)
        chmod(tmp_path, st.st_mode & 0777);
    if (rename(tmp_path, DEFAULT_AUTOSTART_RC) < 0) goto out;
    sync();
    rc = 0;
    goto out;

out_close:
    close(fd);
    fd = -1;
out:
    if (fd >= 0) close(fd);
    unlink(tmp_path);
    remount_root_ro();
    free(buf);
    return rc;
}

static int disable_autostart(int *hook_remove_failed) {
    int rc = 0;

    if (hook_remove_failed) *hook_remove_failed = 0;
    remount_userdata_rw();
    if (unlink(DEFAULT_AUTOSTART_SCRIPT) < 0 && errno != ENOENT)
        rc = -1;
    if (remove_autostart_hook() < 0) {
        rc = -1;
        if (hook_remove_failed) *hook_remove_failed = 1;
    }
    return rc;
}

static void load_web_config(web_config_t *cfg) {
    FILE *fp;
    char line[5000];
    int saw_platform = 0;

    memset(cfg, 0, sizeof(*cfg));
    cfg->port = DEFAULT_WEBUI_PORT;
    safe_copy(cfg->platform, sizeof(cfg->platform), "dingtalk");
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode), "mifi");
    safe_copy(cfg->target_path, sizeof(cfg->target_path), TARGET_MIFI_PATH);
    safe_copy(cfg->custom_ctype, sizeof(cfg->custom_ctype),
              "application/json;charset=utf-8");
    safe_copy(cfg->custom_body, sizeof(cfg->custom_body),
              "{\"text\":\"{{json_text}}\"}");
    fp = fopen(DEFAULT_CONFIG_PATH, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        strip_line(line);
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = 0;
        if (strcmp(line, "webhook") == 0)
            safe_copy(cfg->webhook, sizeof(cfg->webhook), eq);
        else if (strcmp(line, "platform") == 0)
        {
            safe_copy(cfg->platform, sizeof(cfg->platform),
                      normalize_platform(eq));
            saw_platform = 1;
        }
        else if (strcmp(line, "target_mode") == 0)
            safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
                      normalize_target_mode(eq));
        else if (strcmp(line, "target_path") == 0)
            safe_copy(cfg->target_path, sizeof(cfg->target_path), eq);
        else if (strcmp(line, "custom_ctype") == 0)
            safe_copy(cfg->custom_ctype, sizeof(cfg->custom_ctype), eq);
        else if (strcmp(line, "custom_body") == 0)
            config_unescape(cfg->custom_body, sizeof(cfg->custom_body), eq);
        else if (strcmp(line, "num") == 0)
            safe_copy(cfg->num, sizeof(cfg->num), eq);
        else if (strcmp(line, "headtxt") == 0)
            config_unescape(cfg->headtxt, sizeof(cfg->headtxt), eq);
        else if (strcmp(line, "tailtxt") == 0)
            config_unescape(cfg->tailtxt, sizeof(cfg->tailtxt), eq);
        else if (strcmp(line, "port") == 0) {
            long port;
            char *end;
            errno = 0;
            port = strtol(eq, &end, 10);
            if (!errno && end != eq && port > 0 && port <= 65535)
                cfg->port = (int)port;
        }
    }
    fclose(fp);
    if (!saw_platform) {
        safe_copy(cfg->platform, sizeof(cfg->platform),
                  normalize_platform(detect_platform_from_url(cfg->webhook)));
    }
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
              normalize_target_mode(cfg->target_mode));
    remove_newlines(cfg->target_path);
    if (!cfg->target_path[0] || strcmp(cfg->target_mode, "custom") != 0)
        safe_copy(cfg->target_path, sizeof(cfg->target_path),
                  target_default_path(cfg->target_mode));
}

static int save_web_config(const web_config_t *cfg) {
    FILE *fp;
    char esc_body[8192];
    char esc_head[1024];
    char esc_tail[1024];

    if (mkdir_parent_file(DEFAULT_CONFIG_PATH) < 0)
        return -1;
    config_escape(esc_body, sizeof(esc_body), cfg->custom_body);
    config_escape(esc_head, sizeof(esc_head), cfg->headtxt);
    config_escape(esc_tail, sizeof(esc_tail), cfg->tailtxt);
    fp = fopen(DEFAULT_CONFIG_PATH, "w");
    if (!fp) return -1;
    fprintf(fp, "webhook=%s\n", cfg->webhook);
    fprintf(fp, "platform=%s\n", normalize_platform(cfg->platform));
    fprintf(fp, "target_mode=%s\n", normalize_target_mode(cfg->target_mode));
    fprintf(fp, "target_path=%s\n", cfg->target_path);
    fprintf(fp, "custom_ctype=%s\n", cfg->custom_ctype);
    fprintf(fp, "custom_body=%s\n", esc_body);
    fprintf(fp, "num=%s\n", cfg->num);
    fprintf(fp, "headtxt=%s\n", esc_head);
    fprintf(fp, "tailtxt=%s\n", esc_tail);
    fprintf(fp, "port=%d\n", cfg->port > 0 ? cfg->port : DEFAULT_WEBUI_PORT);
    if (fclose(fp) != 0)
        return -1;
    chmod(DEFAULT_CONFIG_PATH, 0600);
    return 0;
}

static void buf_append(char *buf, size_t bufsz, const char *fmt, ...) {
    size_t used;
    va_list ap;

    if (!bufsz) return;
    used = strlen(buf);
    if (used >= bufsz - 1) return;
    va_start(ap, fmt);
    vsnprintf(buf + used, bufsz - used, fmt, ap);
    va_end(ap);
}

static void html_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;
    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        const char *rep = NULL;
        char c = *in++;
        if (c == '&') rep = "&amp;";
        else if (c == '<') rep = "&lt;";
        else if (c == '>') rep = "&gt;";
        else if (c == '"') rep = "&quot;";
        else if (c == '\'') rep = "&#39;";
        if (rep) {
            size_t n = strlen(rep);
            if (used + n >= outsz) break;
            memcpy(out + used, rep, n);
            used += n;
        } else {
            out[used++] = c;
        }
    }
    out[used] = 0;
}

static void json_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;
    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if (c == '"' || c == '\\') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = (char)c;
        } else if (c == '\n' || c == '\r') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = 'n';
        } else if (c < 0x20) {
            continue;
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = 0;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *out, size_t outsz, const char *in, size_t inlen) {
    size_t used = 0;
    size_t i;

    if (!outsz) return;
    for (i = 0; i < inlen && used + 1 < outsz; i++) {
        if (in[i] == '+') {
            out[used++] = ' ';
        } else if (in[i] == '%' && i + 2 < inlen) {
            int a = hexval((unsigned char)in[i + 1]);
            int b = hexval((unsigned char)in[i + 2]);
            if (a >= 0 && b >= 0) {
                out[used++] = (char)((a << 4) | b);
                i += 2;
            } else {
                out[used++] = in[i];
            }
        } else {
            out[used++] = in[i];
        }
    }
    out[used] = 0;
}

static int form_value(const char *body, const char *key, char *out, size_t outsz) {
    const char *p = body;
    size_t keylen = strlen(key);

    if (outsz) out[0] = 0;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
        if (eq && eq < p + pair_len &&
            (size_t)(eq - p) == keylen && strncmp(p, key, keylen) == 0) {
            url_decode(out, outsz, eq + 1, pair_len - keylen - 1);
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int parse_port_text(const char *text, int *port) {
    char *end;
    long value;

    if (!text || !*text)
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || end == text)
        return -1;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
        end++;
    if (*end || value <= 0 || value > 65535)
        return -1;
    *port = (int)value;
    return 0;
}

static void request_webui_restart(int port) {
    g_webui_restart_port = port;
    g_webui_restart_requested = 1;
}

static void restart_webui_process(const char *self_path, int port) {
    pid_t pid = fork();

    if (pid == 0) {
        char port_arg[16];
        const char *self = self_path && self_path[0] ? self_path : "/tmp/alice-pusher-bot";

        snprintf(port_arg, sizeof(port_arg), "%d", port);
        usleep(200000);
        execl(self, self, "-w", "-L", port_arg, (char *)NULL);
        _exit(127);
    }
}

static pid_t read_pid_file(const char *path) {
    FILE *fp = fopen(path, "r");
    long pid = 0;

    if (!fp) return 0;
    fscanf(fp, "%ld", &pid);
    fclose(fp);
    if (pid <= 0 || pid > 999999)
        return 0;
    return (pid_t)pid;
}

static void write_pid_file(const char *path, pid_t pid) {
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "%ld\n", (long)pid);
    fclose(fp);
}

static int process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static pid_t service_pid(void) {
    pid_t pid = read_pid_file(DEFAULT_SERVICE_PID);
    int status = 0;

    if (pid > 0 && waitpid(pid, &status, WNOHANG) == pid) {
        unlink(DEFAULT_SERVICE_PID);
        return 0;
    }
    if (!process_alive(pid)) {
        unlink(DEFAULT_SERVICE_PID);
        return 0;
    }
    return pid;
}

static void cleanup_strace_child(void) {
    pid_t strace_pid = get_strace_pid_from_file();
    web_config_t cfg;
    char target_path[256];

    if (strace_pid > 0 && process_alive(strace_pid)) {
        kill(strace_pid, SIGTERM);
        usleep(200 * 1000);
        if (process_alive(strace_pid))
            kill(strace_pid, SIGKILL);
    }
    load_web_config(&cfg);
    resolve_target_path(&cfg, target_path, sizeof(target_path));
    sigcont_process_by_path(target_path);
    sigcont_process_by_path(g_target_path);
    sigcont_process_by_path(TARGET_MIFI_PATH);
    sigcont_process_by_path(TARGET_UFI_PATH);
}

static int stop_service(void) {
    pid_t pid = read_pid_file(DEFAULT_SERVICE_PID);
    int i;

    if (!process_alive(pid)) {
        unlink(DEFAULT_SERVICE_PID);
        return 0;
    }
    kill(pid, SIGTERM);
    for (i = 0; i < 30; i++) {
        if (!process_alive(pid)) {
            unlink(DEFAULT_SERVICE_PID);
            return 0;
        }
        usleep(100 * 1000);
    }
    kill(pid, SIGKILL);
    usleep(200 * 1000);
    cleanup_strace_child();
    unlink(DEFAULT_SERVICE_PID);
    return 0;
}

static int start_service(const char *self_path, const web_config_t *cfg) {
    pid_t pid;

    if (!cfg->webhook[0]) {
        errno = EINVAL;
        return -1;
    }
    if (service_pid() > 0)
        return 0;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char url_arg[1200];
        char num_arg[180];
        char platform_arg[80];
        char custom_ctype_arg[180];
        char custom_body_arg[2300];
        char head_arg[360];
        char tail_arg[360];
        char target_path[256];
        char target_arg[340];
        char *args[16];
        int n = 0;
        int logfd;

        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_IGN);
        setsid();
        logfd = open(DEFAULT_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            if (logfd > STDERR_FILENO) close(logfd);
        }

        snprintf(url_arg, sizeof(url_arg), "--url=%s", cfg->webhook);
        snprintf(platform_arg, sizeof(platform_arg), "--platform=%s",
                 normalize_platform(cfg->platform));
        snprintf(custom_ctype_arg, sizeof(custom_ctype_arg),
                 "--custom-ctype=%s", cfg->custom_ctype);
        snprintf(custom_body_arg, sizeof(custom_body_arg),
                 "--custom-body=%s", cfg->custom_body);
        snprintf(num_arg, sizeof(num_arg), "--num=%s", cfg->num);
        snprintf(head_arg, sizeof(head_arg), "--headtxt=%s", cfg->headtxt);
        snprintf(tail_arg, sizeof(tail_arg), "--tailtxt=%s", cfg->tailtxt);
        resolve_target_path(cfg, target_path, sizeof(target_path));
        snprintf(target_arg, sizeof(target_arg), "--target-path=%s", target_path);
        args[n++] = (char *)self_path;
        args[n++] = "--mode=service_start";
        args[n++] = url_arg;
        args[n++] = platform_arg;
        args[n++] = target_arg;
        if (strcmp(normalize_platform(cfg->platform), "custom") == 0) {
            args[n++] = custom_ctype_arg;
            args[n++] = custom_body_arg;
        }
        if (cfg->num[0]) args[n++] = num_arg;
        if (cfg->headtxt[0]) args[n++] = head_arg;
        if (cfg->tailtxt[0]) args[n++] = tail_arg;
        args[n] = NULL;
        execv(self_path, args);
        _exit(127);
    }
    write_pid_file(DEFAULT_SERVICE_PID, pid);
    return 0;
}

static void read_log_tail(char *out, size_t outsz) {
	FILE *fp;
	long size;
	long start = 0;
	size_t n;

    if (outsz) out[0] = 0;
    fp = fopen(DEFAULT_LOG_PATH, "r");
    if (!fp) return;
    if (fseek(fp, 0, SEEK_END) == 0) {
        size = ftell(fp);
        if (size > (long)LOG_TAIL_MAX)
            start = size - (long)LOG_TAIL_MAX;
        fseek(fp, start, SEEK_SET);
    }
	n = fread(out, 1, outsz > 0 ? outsz - 1 : 0, fp);
	if (outsz) out[n] = 0;
	fclose(fp);
}

static void resolve_self_path(char *out, size_t outsz, const char *argv0) {
	ssize_t n;

	if (!outsz) return;
	out[0] = 0;
	n = readlink("/proc/self/exe", out, outsz - 1);
	if (n > 0) {
		out[n] = 0;
		return;
	}
	if (argv0 && argv0[0] == '/') {
		safe_copy(out, outsz, argv0);
		return;
	}
	if (argv0 && strchr(argv0, '/')) {
		char cwd[512];
		if (getcwd(cwd, sizeof(cwd))) {
			snprintf(out, outsz, "%s/%s", cwd, argv0);
			return;
		}
	}
	safe_copy(out, outsz, argv0 ? argv0 : "alice-pusher-bot");
}

static int send_all_plain(int fd, const char *buf, size_t len) {
	while (len) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void http_send(int fd, int code, const char *status,
                      const char *ctype, const char *body) {
    char header[256];
    size_t body_len = strlen(body);
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n",
        code, status, ctype, (unsigned long)body_len);
    if (len > 0)
        send_all_plain(fd, header, (size_t)len);
    send_all_plain(fd, body, body_len);
}

static void http_send_data(int fd, int code, const char *status,
                           const char *ctype, const unsigned char *data,
                           size_t data_len, const char *cache) {
    char header[320];
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: %s\r\n"
        "\r\n",
        code, status, ctype, (unsigned long)data_len,
        cache ? cache : "no-store");
    if (len > 0)
        send_all_plain(fd, header, (size_t)len);
    send_all_plain(fd, (const char *)data, data_len);
}

static void append_page_start(char *body, size_t bodysz, const char *active,
                              const char *title, const char *subtitle,
                              const char *message) {
    char esc_msg[1024];
    if (message && message[0])
        html_escape(esc_msg, sizeof(esc_msg), message);
    else
        esc_msg[0] = 0;
    buf_append(body, bodysz,
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%s - Alice Pusher</title><style>"
        "*{box-sizing:border-box}body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}a{color:inherit;text-decoration:none}"
        "@keyframes rise{from{opacity:.62;transform:translateY(7px)}to{opacity:1;transform:none}}"
        ".shell{min-height:100vh;display:grid;grid-template-columns:218px minmax(0,1fr)}.side{position:sticky;top:0;height:100vh;background:#fbfdf9;border-right:1px solid #dbe8dc;padding:18px 14px;display:flex;flex-direction:column;gap:16px}"
        ".brand{font-size:19px;font-weight:800}.sub,.hint{font-size:12px;color:#67786b;margin-top:3px;line-height:1.45}.nav{display:flex;flex-direction:column;gap:6px}.nav a{border-radius:8px;padding:10px 11px;color:#405246;font-size:14px;font-weight:700}.nav a.active,.nav a:hover{background:#dcefe2;color:#1e5e3a}.sidecard{margin-top:auto;border:1px solid #dbe8dc;border-radius:8px;background:#fff;padding:12px}"
        ".pill{display:inline-block;border-radius:999px;padding:6px 10px;background:#2f7d4f;color:#fff;font-size:13px;font-weight:800;white-space:nowrap}.pill.off{background:#7b8a80}"
        "main.page{max-width:1120px;width:100%%;margin:0 auto;padding:22px}.topline{display:flex;justify-content:space-between;gap:14px;margin-bottom:16px}.h1{font-size:25px;font-weight:800}.msg{background:#eef8f0;border:1px solid #c9dfd0;border-radius:8px;color:#235a39;padding:12px 14px;margin-bottom:14px;animation:rise .18s ease-out}"
        ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.panel{background:#fff;border:1px solid #d9e5dc;border-radius:8px;margin-bottom:14px;box-shadow:0 5px 16px rgba(24,37,29,.045);overflow:hidden;animation:rise .22s ease-out}.formtop{border-bottom:1px solid #e7eee8;padding:14px 16px}.title{font-size:16px;font-weight:800}.pad{padding:16px}.kv{border-bottom:1px solid #edf2ee;padding:8px 0}.k{font-size:12px;color:#6d7b71}.v{font-size:14px;font-weight:800;word-break:break-all;margin-top:3px}"
        "label{display:block;font-size:13px;font-weight:800;margin:11px 0 5px}input,textarea,select{width:100%%;border:1px solid #b8c7bb;border-radius:6px;padding:9px 10px;font-size:14px;background:#fff;outline:none}input,select{height:40px}textarea{min-height:84px;resize:vertical}input:focus,textarea:focus,select:focus{border-color:#2f7d4f;box-shadow:0 0 0 3px #dfeee5}.fieldrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.fieldrow button{margin:0}.hint.ok{color:#236a40}.hint.warn{color:#9a5a10}"
        ".custombox{display:none;margin-top:10px;padding:12px;border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;animation:rise .18s ease-out}.custombox.show{display:block}"
        ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}button{height:40px;border:1px solid #2f7d4f;border-radius:6px;background:#2f7d4f;color:#fff;font-size:14px;font-weight:800;padding:0 17px;cursor:pointer}button.alt{background:#fff;color:#2f7d4f}pre,.preview{white-space:pre-wrap;word-break:break-word;background:#101811;color:#d9f5df;border-radius:8px;padding:12px;max-height:520px;overflow:auto}.preview{margin-top:8px;min-height:116px;color:#e3f8e7}"
        ".templates{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.tpl{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:12px}.tplname{font-size:14px;font-weight:800}.tpltext{font-size:12px;color:#56695e;line-height:1.6;margin-top:5px;word-break:break-all}.tplcode{font-family:monospace;background:#eef6ef;border-radius:6px;padding:5px 6px;color:#234732}"
        ".about{display:grid;grid-template-columns:148px minmax(0,1fr);gap:18px;align-items:center}.avatar{width:132px;height:132px;border-radius:8px;object-fit:cover;border:1px solid #d9e5dc;box-shadow:0 8px 22px rgba(24,37,29,.08)}.aboutname{font-size:20px;font-weight:800;margin-bottom:7px}.signature{margin-top:13px;color:#2f5f40;font-size:15px;font-weight:800;line-height:1.7}.repo{display:inline-block;margin-top:13px;color:#1f6d42;font-weight:800;word-break:break-all}.labelrow{margin-top:13px;color:#5f7166;font-size:13px;font-weight:800}.labelrow .repo{margin-top:0}.supporthead{display:block}.supportdesc{color:#405246;font-size:14px;font-weight:700;line-height:1.75;margin-top:7px}.supportgrid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:14px;align-items:stretch}.supportcard{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:14px;min-width:0}.supporttitle{font-size:15px;font-weight:800;margin-bottom:7px}.plainlink{display:inline-block;color:#1f6d42;font-weight:800;word-break:break-all}.qrbox{display:flex;justify-content:center;align-items:center}.qr{display:block;width:100%%;max-width:190px;height:auto;border-radius:8px;border:1px solid #e5dff0;background:#fff;box-shadow:0 8px 18px rgba(24,37,29,.06)}"
        "@media(max-width:820px){.shell{display:block}.side{position:static;height:auto;border-right:0;border-bottom:1px solid #dbe8dc}.nav{flex-direction:row;overflow:auto}.sidecard{display:none}main.page{padding:16px}.grid,.about,.supportgrid,.templates{grid-template-columns:1fr}.topline{display:block}.qr{max-width:220px}}"
        "</style></head><body><div class=\"shell\"><aside class=\"side\">"
        "<div><div class=\"brand\">Alice Pusher</div><div class=\"sub\">短信推送控制台</div></div>"
        "<nav class=\"nav\"><a class=\"%s\" href=\"/\">控制台</a><a class=\"%s\" href=\"/config\">配置</a><a class=\"%s\" href=\"/logs\">运行日志</a><a class=\"%s\" href=\"/about\">关于</a></nav>"
        "<div class=\"sidecard\"><div class=\"hint\">WebUI</div><div class=\"pill\">%d</div></div></aside><main class=\"page\">"
        "<div class=\"topline\"><div><div class=\"h1\">%s</div><div class=\"hint\">%s</div></div></div>",
        title,
        strcmp(active, "home") == 0 ? "active" : "",
        strcmp(active, "config") == 0 ? "active" : "",
        strcmp(active, "logs") == 0 ? "active" : "",
        strcmp(active, "about") == 0 ? "active" : "",
        g_webui_port, title, subtitle);
    if (esc_msg[0])
        buf_append(body, bodysz, "<div class=\"msg\">%s</div>", esc_msg);
}

static void append_page_end(char *body, size_t bodysz) {
    buf_append(body, bodysz,
        "</main></div><script>"
        "function toggleCustom(){var s=document.getElementById('platformSelect'),b=document.getElementById('customFields');if(!s||!b)return;b.className=s.value==='custom'?'custombox show':'custombox';}"
        "function toggleTarget(){var s=document.getElementById('targetModeSelect'),b=document.getElementById('targetCustomFields');if(!s||!b)return;b.className=s.value==='custom'?'custombox show':'custombox';}"
        "function fetchMsisdn(b){var i=document.getElementById('numInput'),m=document.getElementById('numMsg');"
        "if(m){m.textContent='正在读取 nv show...';m.className='hint';}"
        "if(b){b.disabled=true;b.textContent='获取中';}"
        "fetch('/msisdn',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){"
        "if(i&&j.num){i.value=j.num;i.focus();updatePreview();if(m){m.textContent='已读取手机号。';m.className='hint ok';}}"
        "else{if(m){m.textContent='未从 nv show 读取到手机号，请手动填写或留空。';m.className='hint warn';}}"
        "}).catch(function(){if(m){m.textContent='读取失败，请检查设备是否支持 nv show。';m.className='hint warn';}})"
        ".finally(function(){if(b){b.disabled=false;b.textContent='获取';}});}"
        "function enc(s){return encodeURIComponent(s).replace(/[!'()*]/g,function(c){return '%'+c.charCodeAt(0).toString(16).toUpperCase();});}"
        "function jesc(s){return JSON.stringify(s||'').slice(1,-1);}"
        "function barkKey(u){var s=(u||''),i=s.indexOf('://');if(i>=0)s=s.slice(i+3);i=s.indexOf('/');if(i<0)return '';s=s.slice(i+1);if(!s||s.indexOf('push')===0)return '';return s.split(/[/?#]/)[0];}"
        "function sampleText(){var n=document.getElementById('numInput'),num=n&&n.value?n.value:'N/A';return '接收短信设备手机号:'+num+'\\n[pdu解码后的信息]\\n短消息服务中心:+8613800755500\\n发件人:10086\\n时间戳:26/06/30 12:00:00\\n短信内容:Alice Pusher Bot 示例短信';}"
        "function updatePreview(){var h=document.getElementById('headInput'),t=document.getElementById('tailInput'),p=document.getElementById('msgPreview'),s=document.getElementById('platformSelect'),w=document.getElementById('webhookInput'),ct=document.getElementById('ctypeInput'),cb=document.getElementById('customBodyInput');if(!p)return;var a=[],text,plat=s?s.value:'dingtalk',ctype='application/json;charset=utf-8',payload='',jt,key,tmpl;if(h&&h.value)a.push(h.value);a.push(sampleText());if(t&&t.value)a.push(t.value);text=a.join('\\n');if(plat==='serverchan'){ctype='application/x-www-form-urlencoded';payload='title=Alice%20Pusher&desp='+enc(text);}else if(plat==='telegram'){ctype='application/x-www-form-urlencoded';payload='text='+enc(text);}else if(plat==='custom'){ctype=(ct&&ct.value)||'application/json;charset=utf-8';tmpl=(cb&&cb.value)||'{\"text\":\"{{json_text}}\"}';payload=tmpl.split('{{json_text}}').join(jesc(text)).split('{{url_text}}').join(enc(text)).split('{{text}}').join(text);}else{jt=jesc(text);if(plat==='feishu')payload='{\"msg_type\":\"text\",\"content\":{\"text\":\"'+jt+'\"}}';else if(plat==='discord')payload='{\"content\":\"'+jt+'\"}';else if(plat==='bark'){key=barkKey(w&&w.value);payload=key?'{\"title\":\"Alice Pusher\",\"body\":\"'+jt+'\",\"device_key\":\"'+jesc(key)+'\"}':'需要填写 Bark URL 以提取 device_key';}else payload='{\"msgtype\":\"text\",\"text\":{\"content\":\"'+jt+'\"}}';}p.textContent='最终文本:\\n'+text+'\\n\\nContent-Type:\\n'+ctype+'\\n\\nPayload:\\n'+payload;}"
        "toggleCustom();toggleTarget();updatePreview();"
        "</script></body></html>");
}

static void render_home(int fd, const char *message) {
    web_config_t cfg;
    autostart_status_t ast;
    char *body = calloc(1, WEB_BODY_MAX);
    pid_t spid, strpid;
    int target_pid;
    char target_path[256];
    char esc_num[256], esc_hook[256], esc_platform[128];
    char esc_target_label[128], esc_target_path[512];
    const char *auto_label;
    const char *auto_detail;
    const char *auto_payload;

    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    get_autostart_status(&ast);
    spid = service_pid();
    strpid = get_strace_pid_from_file();
    if (!process_alive(strpid)) strpid = 0;
    resolve_target_path(&cfg, target_path, sizeof(target_path));
    target_pid = find_process_by_exe_path(target_path);
    html_escape(esc_num, sizeof(esc_num), cfg.num[0] ? cfg.num : "-");
    html_escape(esc_hook, sizeof(esc_hook), cfg.webhook[0] ? "已配置" : "未配置");
    html_escape(esc_platform, sizeof(esc_platform), platform_label(cfg.platform));
    html_escape(esc_target_label, sizeof(esc_target_label),
                target_mode_label(cfg.target_mode));
    html_escape(esc_target_path, sizeof(esc_target_path), target_path);
    if (ast.run_ready && ast.bin_ready)
        auto_payload = ".run 与二进制已就绪";
    else if (ast.run_ready)
        auto_payload = ".run 已就绪";
    else if (ast.bin_ready)
        auto_payload = "二进制已就绪";
    else
        auto_payload = "待安装";
    if ((ast.run_ready || ast.bin_ready) && ast.script_ready && ast.hook_ready) {
        auto_label = "已启用";
        auto_detail = "开机会启动 Alice Pusher WebUI";
    } else if (ast.script_ready || ast.hook_ready) {
        auto_label = "部分启用";
        auto_detail = "启动脚本或系统钩子不完整，可重新启用修复";
    } else {
        auto_label = "未启用";
        auto_detail = "点击启用时会自动复制当前启动文件";
    }

    append_page_start(body, WEB_BODY_MAX, "home", "控制台",
                      "管理短信推送服务、strace 状态和测试推送", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">运行状态</div></div><div class=\"pad\"><div class=\"grid\">"
        "<div class=\"kv\"><div class=\"k\">服务状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">服务 PID</div><div class=\"v\">%ld</div></div>"
        "<div class=\"kv\"><div class=\"k\">strace PID</div><div class=\"v\">%ld</div></div>"
        "<div class=\"kv\"><div class=\"k\">短信进程</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">进程路径</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">目标 PID</div><div class=\"v\">%d</div></div>"
        "<div class=\"kv\"><div class=\"k\">推送平台</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">Webhook</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">设备手机号</div><div class=\"v\">%s</div></div>"
        "</div><div class=\"actions\">"
        "<form method=\"post\" action=\"/start\"><button type=\"submit\">启动服务</button></form>"
        "<form method=\"post\" action=\"/stop\"><button class=\"alt\" type=\"submit\">停止服务</button></form>"
        "<form method=\"post\" action=\"/restart\"><button class=\"alt\" type=\"submit\">重启服务</button></form>"
        "</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">测试推送</div></div><div class=\"pad\"><form method=\"post\" action=\"/test\">"
        "<label>测试消息</label><textarea name=\"txt\">Alice Pusher Bot 测试消息</textarea>"
        "<div class=\"actions\"><button type=\"submit\">发送测试消息</button></div></form></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">开机自启动</div></div><div class=\"pad\"><div class=\"grid\">"
        "<div class=\"kv\"><div class=\"k\">状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">说明</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">启动文件</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">启动脚本</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">系统钩子</div><div class=\"v\">%s</div></div>"
        "</div><div class=\"actions\">"
        "<form method=\"post\" action=\"/autostart_on\"><button type=\"submit\">启用自启动</button></form>"
        "<form method=\"post\" action=\"/autostart_off\"><button class=\"alt\" type=\"submit\">关闭自启动</button></form>"
        "</div><div class=\"hint\">持久路径：" DEFAULT_RUN_PATH " / " DEFAULT_BIN_PATH "</div></div></section>",
        spid > 0 ? "运行中" : "未运行", (long)spid, (long)strpid,
        esc_target_label, esc_target_path, target_pid > 0 ? target_pid : 0,
        esc_platform, esc_hook, esc_num,
        auto_label, auto_detail, auto_payload,
        ast.script_ready ? "已写入" : "未写入",
        ast.hook_ready ? "已安装" : "未安装");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_config(int fd, const char *message) {
    web_config_t cfg;
    char *body = calloc(1, WEB_BODY_MAX);
    char *custom_body = calloc(1, 12288);
    char webhook[2048], num[256], head[1024], tail[1024];
    char target_path[512];
    char sample_body[1024], sample_final[2048], sample_payload[4096];
    char sample_ctype[160], sample_preview[8192], sample_preview_esc[20000];
    char custom_ctype[256];
    int port;

    if (!body || !custom_body) {
        free(body);
        free(custom_body);
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    html_escape(webhook, sizeof(webhook), cfg.webhook);
    html_escape(num, sizeof(num), cfg.num);
    html_escape(head, sizeof(head), cfg.headtxt);
    html_escape(tail, sizeof(tail), cfg.tailtxt);
    html_escape(target_path, sizeof(target_path), cfg.target_path);
    html_escape(custom_ctype, sizeof(custom_ctype), cfg.custom_ctype);
    html_escape(custom_body, 12288, cfg.custom_body);
    snprintf(sample_body, sizeof(sample_body),
             "接收短信设备手机号:%s\n[pdu解码后的信息]\n短消息服务中心:+8613800755500\n发件人:10086\n时间戳:26/06/30 12:00:00\n短信内容:Alice Pusher Bot 示例短信",
             cfg.num[0] ? cfg.num : "N/A");
    build_push_message(sample_final, sizeof(sample_final),
                       cfg.headtxt, sample_body, cfg.tailtxt);
    if (build_webhook_payload(cfg.webhook, cfg.platform, sample_final,
                              cfg.custom_ctype, cfg.custom_body,
                              sample_payload, sizeof(sample_payload),
                              sample_ctype, sizeof(sample_ctype)) < 0) {
        safe_copy(sample_ctype, sizeof(sample_ctype), "-");
        safe_copy(sample_payload, sizeof(sample_payload),
                  "无法生成 Payload：请检查平台、Webhook 或自定义模板。");
    }
    snprintf(sample_preview, sizeof(sample_preview),
             "最终文本:\n%s\n\nContent-Type:\n%s\n\nPayload:\n%s",
             sample_final, sample_ctype, sample_payload);
    html_escape(sample_preview_esc, sizeof(sample_preview_esc), sample_preview);
    port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    append_page_start(body, WEB_BODY_MAX, "config", "配置",
                      "保存 webhook、手机号、推送文本和平台", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">WebUI 设置</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/set_port\">"
        "<label>WebUI 端口</label><input name=\"port\" value=\"%d\" inputmode=\"numeric\" pattern=\"[0-9]*\" required>"
        "<div class=\"actions\"><button type=\"submit\">保存并切换端口</button></div>"
        "</form><div class=\"hint\">端口默认保存到 " DEFAULT_CONFIG_PATH "。修改后 WebUI 会立即切换到新端口。</div>"
        "</div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">推送配置</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/save_config\">"
        "<label>短信进程</label><select id=\"targetModeSelect\" name=\"target_mode\" onchange=\"toggleTarget()\">"
        "<option value=\"mifi\"%s>ZTE MiFi（/sbin/zte_mifi）</option>"
        "<option value=\"ufi\"%s>ZTE UFI（/sbin/zte_ufi）</option>"
        "<option value=\"custom\"%s>自定义路径</option>"
        "</select>"
        "<div id=\"targetCustomFields\" class=\"custombox\">"
        "<label>自定义进程路径</label><input name=\"target_path\" value=\"%s\" placeholder=\"/sbin/zte_mifi\">"
        "<div class=\"hint\">填写 /proc/&lt;pid&gt;/exe 指向的可执行文件路径。保存后重启服务生效。</div>"
        "</div>"
        "<label>推送平台</label><select id=\"platformSelect\" name=\"platform\" onchange=\"toggleCustom();updatePreview()\">"
        "<option value=\"dingtalk\"%s>钉钉</option>"
        "<option value=\"feishu\"%s>飞书</option>"
        "<option value=\"wecom\"%s>企业微信</option>"
        "<option value=\"serverchan\"%s>Server 酱</option>"
        "<option value=\"discord\"%s>Discord</option>"
        "<option value=\"telegram\"%s>Telegram Bot</option>"
        "<option value=\"bark\"%s>Bark</option>"
        "<option value=\"custom\"%s>自定义</option>"
        "</select>"
        "<label>Webhook URL</label><textarea id=\"webhookInput\" name=\"webhook\" required oninput=\"updatePreview()\">%s</textarea>"
        "<div id=\"customFields\" class=\"custombox\">"
        "<label>自定义 Content-Type</label><input id=\"ctypeInput\" name=\"custom_ctype\" value=\"%s\" oninput=\"updatePreview()\">"
        "<label>自定义消息体模板</label><textarea id=\"customBodyInput\" name=\"custom_body\" rows=\"8\" oninput=\"updatePreview()\">%s</textarea>"
        "<div class=\"hint\">占位符：{{json_text}} 适合 JSON 字符串，{{url_text}} 适合表单或 URL 编码，{{text}} 为原文。</div>"
        "</div>"
        "<label>设备手机号，可留空自动读取 nv show</label><div class=\"fieldrow\"><input id=\"numInput\" name=\"num\" value=\"%s\" oninput=\"updatePreview()\"><button class=\"alt\" type=\"button\" onclick=\"fetchMsisdn(this)\">获取</button></div><div id=\"numMsg\" class=\"hint\">获取不到时可手动填写，也可以留空。</div>"
        "<label>消息前缀</label><textarea id=\"headInput\" name=\"headtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>消息后缀</label><textarea id=\"tailInput\" name=\"tailtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>发送内容示例（按当前平台编码）</label><div id=\"msgPreview\" class=\"preview\">%s</div>"
        "<div class=\"actions\"><button type=\"submit\">保存配置</button></div>"
        "</form><div class=\"hint\">配置保存到 " DEFAULT_CONFIG_PATH "，权限 0600。</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">Webhook 模板</div></div><div class=\"pad templates\">"
        "<div class=\"tpl\"><div class=\"tplname\">钉钉</div><div class=\"tpltext\">机器人地址一般形如 <span class=\"tplcode\">https://oapi.dingtalk.com/robot/send?access_token=...</span>。消息体使用 text 类型：<span class=\"tplcode\">msgtype/text/content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">飞书</div><div class=\"tpltext\">自定义机器人地址一般形如 <span class=\"tplcode\">https://open.feishu.cn/open-apis/bot/v2/hook/...</span>。消息体使用 text 类型：<span class=\"tplcode\">msg_type/content/text</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">企业微信</div><div class=\"tpltext\">群机器人地址一般形如 <span class=\"tplcode\">https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...</span>。消息体使用 text 类型：<span class=\"tplcode\">msgtype/text/content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Server 酱</div><div class=\"tpltext\">SendKey 地址一般形如 <span class=\"tplcode\">https://sctapi.ftqq.com/SENDKEY.send</span>。消息体使用表单字段：<span class=\"tplcode\">title/desp</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Discord</div><div class=\"tpltext\">Webhook 地址形如 <span class=\"tplcode\">https://discord.com/api/webhooks/...</span>。消息体使用 JSON 字段：<span class=\"tplcode\">content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Telegram Bot</div><div class=\"tpltext\">URL 写成 <span class=\"tplcode\">https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHAT_ID</span>。消息体使用表单字段：<span class=\"tplcode\">text</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Bark</div><div class=\"tpltext\">URL 写成 <span class=\"tplcode\">https://api.day.app/your_key</span>。程序会提取 key 并向 <span class=\"tplcode\">/push</span> 发送 JSON：<span class=\"tplcode\">device_key/title/body</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">自定义</div><div class=\"tpltext\">自行填写 Content-Type 与消息体模板。JSON 示例：<span class=\"tplcode\">{&quot;text&quot;:&quot;{{json_text}}&quot;}</span>；表单示例：<span class=\"tplcode\">title=Alice&amp;desp={{url_text}}</span>。</div></div>"
        "</div></section>",
        port,
        target_selected_attr(cfg.target_mode, "mifi"),
        target_selected_attr(cfg.target_mode, "ufi"),
        target_selected_attr(cfg.target_mode, "custom"),
        target_path,
        selected_attr(cfg.platform, "dingtalk"),
        selected_attr(cfg.platform, "feishu"),
        selected_attr(cfg.platform, "wecom"),
        selected_attr(cfg.platform, "serverchan"),
        selected_attr(cfg.platform, "discord"),
        selected_attr(cfg.platform, "telegram"),
        selected_attr(cfg.platform, "bark"),
        selected_attr(cfg.platform, "custom"),
        webhook, custom_ctype, custom_body, num,
        head, tail, sample_preview_esc);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(custom_body);
    free(body);
}

static void render_logs(int fd, const char *message) {
    char *body = calloc(1, WEB_BODY_MAX);
    char *logbuf = calloc(1, LOG_TAIL_MAX + 1);
    char *esc = calloc(1, LOG_TAIL_MAX * 6 + 1);

    if (!body || !logbuf || !esc) {
        free(body); free(logbuf); free(esc);
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    read_log_tail(logbuf, LOG_TAIL_MAX + 1);
    html_escape(esc, LOG_TAIL_MAX * 6 + 1, logbuf[0] ? logbuf : "暂无日志");
    append_page_start(body, WEB_BODY_MAX, "logs", "运行日志",
                      "显示 /tmp/alice_pusher.log 最近内容", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">日志</div></div><div class=\"pad\"><pre>%s</pre>"
        "<div class=\"actions\"><form method=\"get\" action=\"/logs\"><button class=\"alt\" type=\"submit\">刷新</button></form></div></div></section>",
        esc);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body); free(logbuf); free(esc);
}

static void render_about(int fd) {
    char *body = calloc(1, WEB_BODY_MAX);
    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    append_page_start(body, WEB_BODY_MAX, "about", "关于",
                      "项目信息与署名", NULL);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"pad about\">"
        "<img class=\"avatar\" src=\"/avatar.jpg\" alt=\"avatar\">"
        "<div><div class=\"aboutname\">alice-pusher-bot-zxic</div>"
        "<div class=\"hint\">ZTE MiFi/UFI 短信捕获与 Webhook 推送工具</div>"
        "<div class=\"labelrow\">项目地址：<a class=\"repo\" href=\"https://github.com/Amamiyashi0n/alice-pusher-bot-zxic\">"
        "github.com/Amamiyashi0n/alice-pusher-bot-zxic</a></div>"
        "<div class=\"signature\">世间自有尘寰在，我亦独吟游且歌。</div>"
        "</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"supporthead\">"
        "<div class=\"title\">赞助支持</div>"
        "<div class=\"supportdesc\">软件免费，代码开源。<br>"
        "如果可以的话，也许您可以给予我一些小小的帮助。</div></div></div>"
        "<div class=\"pad supportgrid\">"
        "<div class=\"supportcard\"><div class=\"supporttitle\">微信 / 支付宝扫码</div>"
        "<div class=\"qrbox\"><img class=\"qr\" src=\"/sponsor.jpg\" alt=\"sponsor qrcode\"></div>"
        "</div><div class=\"supportcard\"><div class=\"supporttitle\">爱发电</div>"
        "<a class=\"plainlink\" href=\"https://ifdian.net/a/amamiyashion\">"
        "ifdian.net/a/amamiyashion</a>"
        "</div></div></section>");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_avatar(int fd) {
    http_send_data(fd, 200, "OK", avatar_image_mime,
                   avatar_image_data, avatar_image_size,
                   "public, max-age=86400");
}

static void render_sponsor_image(int fd) {
    http_send_data(fd, 200, "OK", sponsor_image_mime,
                   sponsor_image_data, sponsor_image_size,
                   "public, max-age=86400");
}

static void render_status_json(int fd) {
    web_config_t cfg;
    char num[256];
    char platform[96];
    char target_mode[64];
    char target_path[512];
    char target_path_raw[256];
    pid_t spid = service_pid();
    pid_t strpid = get_strace_pid_from_file();
    int target_pid;
    char body[2048];

    load_web_config(&cfg);
    if (!process_alive(strpid)) strpid = 0;
    resolve_target_path(&cfg, target_path_raw, sizeof(target_path_raw));
    target_pid = find_process_by_exe_path(target_path_raw);
    json_escape(num, sizeof(num), cfg.num);
    json_escape(platform, sizeof(platform), platform_label(cfg.platform));
    json_escape(target_mode, sizeof(target_mode), target_mode_label(cfg.target_mode));
    json_escape(target_path, sizeof(target_path), target_path_raw);
    snprintf(body, sizeof(body),
        "{\"service_running\":%s,\"service_pid\":%ld,"
        "\"strace_pid\":%ld,\"target_pid\":%d,\"zte_mifi_pid\":%d,"
        "\"target_mode\":\"%s\",\"target_path\":\"%s\","
        "\"webhook_configured\":%s,\"platform\":\"%s\","
        "\"num\":\"%s\",\"port\":%d}\n",
        spid > 0 ? "true" : "false", (long)spid, (long)strpid,
        target_pid > 0 ? target_pid : 0,
        target_pid > 0 ? target_pid : 0, target_mode, target_path,
        cfg.webhook[0] ? "true" : "false", platform, num, g_webui_port);
    http_send(fd, 200, "OK", "application/json; charset=utf-8", body);
}

static void render_msisdn_json(int fd) {
    char num[256];
    char body[640];

    load_device_msisdn_from_nv_show();
    json_escape(num, sizeof(num), device_msisdn);
    snprintf(body, sizeof(body),
             "{\"ok\":%s,\"num\":\"%s\",\"message\":\"%s\"}\n",
             device_msisdn[0] ? "true" : "false", num,
             device_msisdn[0] ? "已读取手机号" :
             "未从 nv show 读取到手机号");
    http_send(fd, 200, "OK", "application/json; charset=utf-8", body);
}

static void handle_save_config(int fd, const char *body) {
    web_config_t cfg;
    int saved_port;

    load_web_config(&cfg);
    saved_port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    form_value(body, "webhook", cfg.webhook, sizeof(cfg.webhook));
    form_value(body, "platform", cfg.platform, sizeof(cfg.platform));
    form_value(body, "target_mode", cfg.target_mode, sizeof(cfg.target_mode));
    form_value(body, "target_path", cfg.target_path, sizeof(cfg.target_path));
    form_value(body, "custom_ctype", cfg.custom_ctype,
               sizeof(cfg.custom_ctype));
    form_value(body, "custom_body", cfg.custom_body,
               sizeof(cfg.custom_body));
    form_value(body, "num", cfg.num, sizeof(cfg.num));
    form_value(body, "headtxt", cfg.headtxt, sizeof(cfg.headtxt));
    form_value(body, "tailtxt", cfg.tailtxt, sizeof(cfg.tailtxt));
    cfg.port = saved_port;
    remove_newlines(cfg.webhook);
    safe_copy(cfg.platform, sizeof(cfg.platform),
              normalize_platform(cfg.platform));
    safe_copy(cfg.target_mode, sizeof(cfg.target_mode),
              normalize_target_mode(cfg.target_mode));
    remove_newlines(cfg.target_path);
    if (strcmp(cfg.target_mode, "custom") != 0) {
        safe_copy(cfg.target_path, sizeof(cfg.target_path),
                  target_default_path(cfg.target_mode));
    } else if (!cfg.target_path[0] || cfg.target_path[0] != '/') {
        render_config(fd, "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。");
        return;
    }
    remove_newlines(cfg.custom_ctype);
    if (!cfg.custom_ctype[0])
        safe_copy(cfg.custom_ctype, sizeof(cfg.custom_ctype),
                  "application/json;charset=utf-8");
    remove_newlines(cfg.num);
    if (!cfg.webhook[0]) {
        render_config(fd, "Webhook 不能为空。");
        return;
    }
    if (strcmp(normalize_platform(cfg.platform), "custom") == 0 &&
        !cfg.custom_body[0]) {
        render_config(fd, "自定义消息体模板不能为空。");
        return;
    }
    if (save_web_config(&cfg) < 0) {
        render_config(fd, "配置保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    render_config(fd, "配置已保存。");
}

static void handle_set_port(int fd, const char *body) {
    web_config_t cfg;
    char value[32];
    char response[1024];
    int port;

    load_web_config(&cfg);
    form_value(body, "port", value, sizeof(value));
    if (parse_port_text(value, &port) < 0) {
        render_config(fd, "端口无效，请输入 1-65535。");
        return;
    }
    cfg.port = port;
    if (save_web_config(&cfg) < 0) {
        render_config(fd, "端口保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    if (port == g_webui_port) {
        render_config(fd, "WebUI 端口已保存。");
        return;
    }

    snprintf(response, sizeof(response),
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>WebUI 端口已切换</title>"
        "<style>body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}"
        ".box{max-width:560px;margin:12vh auto;padding:22px;background:#fff;border:1px solid #d9e5dc;border-radius:8px;box-shadow:0 8px 24px rgba(24,37,29,.06)}"
        ".h{font-size:22px;font-weight:800}.p{color:#55685c;line-height:1.7}.a{display:inline-block;margin-top:10px;color:#1f6d42;font-weight:800}</style>"
        "</head><body><div class=\"box\"><div class=\"h\">WebUI 端口已保存</div>"
        "<div class=\"p\">服务正在切换到 %d 端口。请打开新地址继续访问。</div>"
        "<a class=\"a\" href=\"http://127.0.0.1:%d/\">http://127.0.0.1:%d/</a>"
        "</div></body></html>",
        port, port, port);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", response);
    request_webui_restart(port);
}

static void handle_autostart_on(int fd) {
    if (write_autostart_script() < 0) {
        render_home(fd, "自启动脚本写入失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    if (install_autostart_hook() < 0) {
        render_home(fd, "自启动脚本已写入，但 /etc/rc 钩子安装失败。");
        return;
    }
    render_home(fd, "开机自启动已启用。");
}

static void handle_autostart_off(int fd) {
    int hook_failed = 0;

    if (disable_autostart(&hook_failed) < 0) {
        render_home(fd, hook_failed ?
                    "自启动脚本已尝试删除，但 /etc/rc 钩子移除失败。" :
                    "关闭自启动失败，请检查持久分区状态。");
        return;
    }
    render_home(fd, "开机自启动已关闭。");
}

static void handle_start(int fd, const char *self_path) {
    web_config_t cfg;
    load_web_config(&cfg);
    if (start_service(self_path, &cfg) < 0) {
        render_home(fd, "启动失败：请先保存有效 Webhook，或查看日志。");
        return;
    }
    render_home(fd, "服务已启动。");
}

static void handle_stop(int fd) {
    stop_service();
    render_home(fd, "服务已停止。");
}

static void handle_restart(int fd, const char *self_path) {
    web_config_t cfg;
    load_web_config(&cfg);
    stop_service();
    if (start_service(self_path, &cfg) < 0) {
        render_home(fd, "重启失败：请先保存有效 Webhook，或查看日志。");
        return;
    }
    render_home(fd, "服务已重启。");
}

static int run_test_message(const char *self_path, const web_config_t *cfg,
                            const char *txt) {
    pid_t pid;
    int status = 0;
    char final_txt[2048];

    build_push_message(final_txt, sizeof(final_txt),
                       cfg->headtxt, txt, cfg->tailtxt);

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char url_arg[1200];
        char txt_arg[2300];
        char platform_arg[80];
        char custom_ctype_arg[180];
        char custom_body_arg[2300];
        char *args[10];
        int n = 0;
        int logfd;

        logfd = open(DEFAULT_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            if (logfd > STDERR_FILENO) close(logfd);
        }
        snprintf(url_arg, sizeof(url_arg), "--url=%s", cfg->webhook);
        snprintf(platform_arg, sizeof(platform_arg), "--platform=%s",
                 normalize_platform(cfg->platform));
        snprintf(custom_ctype_arg, sizeof(custom_ctype_arg),
                 "--custom-ctype=%s", cfg->custom_ctype);
        snprintf(custom_body_arg, sizeof(custom_body_arg),
                 "--custom-body=%s", cfg->custom_body);
        snprintf(txt_arg, sizeof(txt_arg), "--txt=%s", final_txt);
        args[n++] = (char *)self_path;
        args[n++] = "--mode=send_once";
        args[n++] = url_arg;
        args[n++] = platform_arg;
        if (strcmp(normalize_platform(cfg->platform), "custom") == 0) {
            args[n++] = custom_ctype_arg;
            args[n++] = custom_body_arg;
        }
        args[n++] = "--msgtype=text";
        args[n++] = txt_arg;
        args[n] = NULL;
        execv(self_path, args);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

static void handle_test(int fd, const char *self_path, const char *body) {
    web_config_t cfg;
    char txt[1024];

    load_web_config(&cfg);
    if (!cfg.webhook[0]) {
        render_home(fd, "请先保存 Webhook。");
        return;
    }
    if (!form_value(body, "txt", txt, sizeof(txt)) || !txt[0])
        safe_copy(txt, sizeof(txt), "Alice Pusher Bot 测试消息");
    remove_newlines(txt);
    if (run_test_message(self_path, &cfg, txt) == 0)
        render_home(fd, "测试消息已发送，请检查 Webhook 返回和运行日志。");
    else
        render_home(fd, "测试消息发送失败，请检查 Webhook 和运行日志。");
}

static int read_http_request(int fd, char *req, size_t reqsz, char **body_out) {
    size_t used = 0;
    int content_len = 0;
    char *hdr_end = NULL;

    if (body_out) *body_out = NULL;
    while (used + 1 < reqsz) {
        ssize_t n = recv(fd, req + used, reqsz - used - 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        used += (size_t)n;
        req[used] = 0;
        hdr_end = strstr(req, "\r\n\r\n");
        if (hdr_end) {
            char *cl = strstr(req, "Content-Length:");
            if (!cl) cl = strstr(req, "content-length:");
            if (cl) content_len = atoi(cl + 15);
            if ((size_t)(hdr_end + 4 - req) + (size_t)content_len <= used)
                break;
        }
    }
    if (!hdr_end)
        hdr_end = strstr(req, "\r\n\r\n");
    if (!hdr_end)
        return -1;
    if (body_out)
        *body_out = hdr_end + 4;
    return 0;
}

static void handle_http_client(int fd, const char *self_path) {
    char req[WEB_REQ_MAX];
    char method[8];
    char path[256];
    char *body;

    memset(req, 0, sizeof(req));
    if (read_http_request(fd, req, sizeof(req), &body) < 0) {
        http_send(fd, 400, "Bad Request", "text/plain", "bad request\n");
        return;
    }
    if (sscanf(req, "%7s %255s", method, path) != 2) {
        http_send(fd, 400, "Bad Request", "text/plain", "bad request\n");
        return;
    }
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0) render_home(fd, NULL);
        else if (strcmp(path, "/config") == 0) render_config(fd, NULL);
        else if (strcmp(path, "/logs") == 0) render_logs(fd, NULL);
        else if (strcmp(path, "/about") == 0) render_about(fd);
        else if (strcmp(path, "/avatar.jpg") == 0) render_avatar(fd);
        else if (strcmp(path, "/sponsor.jpg") == 0) render_sponsor_image(fd);
        else if (strcmp(path, "/status") == 0) render_status_json(fd);
        else if (strcmp(path, "/msisdn") == 0) render_msisdn_json(fd);
        else http_send(fd, 404, "Not Found", "text/plain", "not found\n");
        return;
    }
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/save_config") == 0) handle_save_config(fd, body);
        else if (strcmp(path, "/set_port") == 0) handle_set_port(fd, body);
        else if (strcmp(path, "/autostart_on") == 0) handle_autostart_on(fd);
        else if (strcmp(path, "/autostart_off") == 0) handle_autostart_off(fd);
        else if (strcmp(path, "/start") == 0) handle_start(fd, self_path);
        else if (strcmp(path, "/stop") == 0) handle_stop(fd);
        else if (strcmp(path, "/restart") == 0) handle_restart(fd, self_path);
        else if (strcmp(path, "/test") == 0) handle_test(fd, self_path, body);
        else http_send(fd, 404, "Not Found", "text/plain", "not found\n");
        return;
    }
    http_send(fd, 405, "Method Not Allowed", "text/plain", "method not allowed\n");
}

static int run_webui(const char *self_path, int port) {
    int sfd;
    int yes = 1;
    struct sockaddr_in addr;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    if (port <= 0 || port > 65535)
        port = DEFAULT_WEBUI_PORT;
    g_webui_port = port;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sfd);
        return 1;
    }
    if (listen(sfd, 8) < 0) {
        perror("listen");
        close(sfd);
        return 1;
    }
    printf("Alice Pusher WebUI listening on 0.0.0.0:%d\n", port);
    fflush(stdout);
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        handle_http_client(cfd, self_path);
        close(cfd);
        if (g_webui_restart_requested)
            break;
    }
    close(sfd);
    if (g_webui_restart_requested) {
        restart_webui_process(self_path, g_webui_restart_port);
        _exit(0);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int only_service_mode = 0;
    int only_send_once_mode = 0;
    int webui_mode = 0;
    int webui_port = DEFAULT_WEBUI_PORT;
    web_config_t saved_cfg;
    char *manual_msisdn = NULL;
    char *cli_platform = NULL;
    char *cli_custom_ctype = NULL;
    char *cli_custom_body = NULL;
    char *cli_url = NULL;
    char *cli_msgtype = NULL;
    char *cli_txt = NULL;
    char *cli_headtxt = NULL;
    char *cli_tailtxt = NULL;
    char *cli_target_path = NULL;
    int i;

    load_web_config(&saved_cfg);
    if (saved_cfg.port > 0 && saved_cfg.port <= 65535)
        webui_port = saved_cfg.port;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--webui") == 0) {
            webui_mode = 1;
        }
        if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            webui_port = atoi(argv[++i]);
        }
        if (strncmp(argv[i], "--port=", 7) == 0) {
            webui_port = atoi(argv[i] + 7);
        }
        if ((strcmp(argv[i], "--mode=service_start") == 0)) {
            only_service_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=send_once") == 0)) { // 新增
            only_send_once_mode = 1;
        }
        if (strncmp(argv[i], "--num=", 6) == 0) {
            manual_msisdn = argv[i] + 6;
        }
        if (strncmp(argv[i], "--platform=", 11) == 0) {
            cli_platform = argv[i] + 11;
        }
        if (strncmp(argv[i], "--custom-ctype=", 15) == 0) {
            cli_custom_ctype = argv[i] + 15;
        }
        if (strncmp(argv[i], "--custom-body=", 14) == 0) {
            cli_custom_body = argv[i] + 14;
        }
        if (strncmp(argv[i], "--url=", 6) == 0) {
            cli_url = argv[i] + 6;
        }
        if (strncmp(argv[i], "--msgtype=", 10) == 0) {
            cli_msgtype = argv[i] + 10;
        }
        if (strncmp(argv[i], "--txt=", 6) == 0) {
            cli_txt = argv[i] + 6;
        }
        if (strncmp(argv[i], "--headtxt=", 10) == 0) {
            cli_headtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--tailtxt=", 10) == 0) {
            cli_tailtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--target-path=", 14) == 0) {
            cli_target_path = argv[i] + 14;
        }
        if (strncmp(argv[i], "--targetbin=", 12) == 0) {
            cli_target_path = argv[i] + 12;
        }
    }
    if (webui_mode) {
        char self_path[512];
        resolve_self_path(self_path, sizeof(self_path), argv[0]);
        return run_webui(self_path, webui_port);
    }
    if (only_service_mode) {
        const char *platform;
        if (!cli_url || strlen(cli_url) == 0) {
            fprintf(stderr, "Error: --mode=service_start 时必须指定 --url=<webhook_url> 参数！\n");
            return 1;
        }
        platform = normalize_platform(cli_platform && cli_platform[0] ?
                                      cli_platform :
                                      detect_platform_from_url(cli_url));
        if (!cli_target_path || !cli_target_path[0])
            cli_target_path = TARGET_MIFI_PATH;
        safe_copy(g_target_path, sizeof(g_target_path), cli_target_path);
        if (manual_msisdn && manual_msisdn[0]) {
            strncpy(device_msisdn, manual_msisdn, sizeof(device_msisdn) - 1);
            device_msisdn[sizeof(device_msisdn) - 1] = 0;
        } else {
            load_device_msisdn_from_nv_show();
            if (!device_msisdn[0]) {
                strncpy(device_msisdn, "读取手机号失败 请使用 --num=参数进行手动添加", sizeof(device_msisdn) - 1);
                device_msisdn[sizeof(device_msisdn) - 1] = 0;
            }
        }
        printf("Alice Pushbot - Service mode starting.\n");
        printf("Target: %s (strace attached).\n", g_target_path);
        printf("Press Ctrl+C to stop.\n");
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        if (pthread_create(&strace_thread_id, NULL, strace_thread_func, g_target_path) != 0) {
            perror("Failed to create strace thread");
            return 1;
        }
        char* pdu_args[6] = {
            cli_url, (char *)platform, cli_custom_ctype, cli_custom_body,
            cli_headtxt, cli_tailtxt
        };
        if (pthread_create(&pdu_thread_id, NULL, pdu_thread_func, pdu_args) != 0) {
            perror("Failed to create PDU thread");
            return 1;
        }
        pthread_join(strace_thread_id, NULL);
        pthread_join(pdu_thread_id, NULL);
        return 0;
    }
    if (only_send_once_mode || cli_url || cli_txt) {
        const char *platform;
        char final_txt[2048];
        if (!cli_url || !cli_msgtype || !cli_txt) {
            fprintf(stderr, "Usage: %s --mode=send_once --url=<webhook_url> --platform=<dingtalk|feishu|wecom|serverchan|discord|telegram|bark|custom> [--custom-ctype=<content-type>] [--custom-body=<template>] [--headtxt=<prefix>] [--tailtxt=<suffix>] --msgtype=text --txt=<content>\n", argv[0]);
            return 1;
        }
        if (strcmp(cli_msgtype, "text") != 0) {
            fprintf(stderr, "Only msgtype=text is supported.\n");
            return 1;
        }
        platform = normalize_platform(cli_platform && cli_platform[0] ?
                                      cli_platform :
                                      detect_platform_from_url(cli_url));
        build_push_message(final_txt, sizeof(final_txt),
                           cli_headtxt, cli_txt, cli_tailtxt);
        return send_webhook_msg(cli_url, platform, final_txt,
                                cli_custom_ctype, cli_custom_body) == 0 ? 0 : 1;
    }

    fprintf(stderr, "Usage: %s -w | --mode=send_once --url=<webhook_url> --platform=<dingtalk|feishu|wecom|serverchan|discord|telegram|bark|custom> [--custom-ctype=<content-type>] [--custom-body=<template>] [--headtxt=<prefix>] [--tailtxt=<suffix>] --msgtype=text --txt=<content>\n", argv[0]);
    return 1;
}
