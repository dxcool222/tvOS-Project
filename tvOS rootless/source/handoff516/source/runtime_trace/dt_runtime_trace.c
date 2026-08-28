#include "dt_runtime_trace.h"

#include <errno.h>
#include <fcntl.h>
#include <os/log.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static void dt_r24_sanitize(char *value)
{
	if (!value)
		return;
	for (char *p = value; *p; p++) {
		if (*p == '\n' || *p == '\r' || *p == '\t')
			*p = ' ';
	}
}

int dt_r24_trace_event(const char *component, const char *event, int rc,
			       int error_number, const char *detail)
{
	char component_buf[64];
	char event_buf[128];
	char detail_buf[768];
	strlcpy(component_buf, component ? component : "UNKNOWN", sizeof(component_buf));
	strlcpy(event_buf, event ? event : "UNKNOWN", sizeof(event_buf));
	strlcpy(detail_buf, detail ? detail : "-", sizeof(detail_buf));
	dt_r24_sanitize(component_buf);
	dt_r24_sanitize(event_buf);
	dt_r24_sanitize(detail_buf);

	struct timespec ts = {0};
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	char line[1200];
	int length = snprintf(line, sizeof(line),
	    "R24TRACE t=%lld.%09ld component=%s pid=%d event=%s rc=%d errno=%d detail=%s\n",
	    (long long)ts.tv_sec, ts.tv_nsec, component_buf, getpid(), event_buf, rc,
	    error_number, detail_buf);
	if (length <= 0 || (size_t)length >= sizeof(line))
		return -1;

	os_log(OS_LOG_DEFAULT,
	    "R24TRACE component=%{public}s pid=%{public}d event=%{public}s rc=%{public}d errno=%{public}d detail=%{public}s",
	    component_buf, getpid(), event_buf, rc, error_number, detail_buf);

	int fd = open(DT_R24_RUNTIME_TRACE_PATH,
	              O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0666);
	if (fd < 0)
		return -2;
	struct stat st = {0};
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0) {
		close(fd);
		return -3;
	}
	if ((unsigned long long)st.st_size >= DT_R24_RUNTIME_TRACE_MAX_BYTES) {
		close(fd);
		return -4;
	}
	ssize_t wrote = write(fd, line, (size_t)length);
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return wrote == length ? 0 : -5;
}
