#import "spawn_root.h"

#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <Foundation/Foundation.h>
#import <sys/select.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

static int dt_spawn_capture_internal(NSString *binaryPath,
                                     NSArray<NSString *> *args,
                                     BOOL usePersona,
                                     int *exitStatusOut,
                                     int *waitStatusOut,
                                     NSString **stdoutOut,
                                     NSError **errorOut)
{
    if (binaryPath.length == 0) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"empty binary path"}];
        }
        return -1;
    }

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    typedef int (*posix_spawnattr_init_fn)(posix_spawnattr_t *);
    typedef int (*posix_spawnattr_destroy_fn)(posix_spawnattr_t *);
    typedef int (*spawn_fa_init_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
    typedef int (*spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

    void *lib = RTLD_DEFAULT;
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(lib, "posix_spawn");
    posix_spawnattr_init_fn attr_init = (posix_spawnattr_init_fn)dlsym(lib, "posix_spawnattr_init");
    posix_spawnattr_destroy_fn attr_destroy = (posix_spawnattr_destroy_fn)dlsym(lib, "posix_spawnattr_destroy");
    if (!spawn || !attr_init || !attr_destroy) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"posix_spawn unavailable"}];
        }
        return -1;
    }

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:binaryPath.lastPathComponent];
    [argvStrings addObjectsFromArray:args ?: @[]];

    NSUInteger argc = argvStrings.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv)
        return -1;
    for (NSUInteger i = 0; i < argc; i++)
        argv[i] = strdup(argvStrings[i].UTF8String);

    posix_spawnattr_t attr;
    posix_spawnattr_t *attrPtr = NULL;
    if (usePersona) {
        if (attr_init(&attr) != 0) {
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            return -1;
        }
        attrPtr = &attr;
        int pErr = posix_spawnattr_set_persona_np(&attr, 99, DT_POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        int uErr = posix_spawnattr_set_persona_uid_np(&attr, 0);
        int gErr = posix_spawnattr_set_persona_gid_np(&attr, 0);
        if (pErr != 0 || uErr != 0 || gErr != 0) {
            attr_destroy(&attr);
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (errorOut) {
                *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:EINVAL
                                            userInfo:@{NSLocalizedDescriptionKey :
                                                           [NSString stringWithFormat:
                                                               @"persona attr set failed persona=%d uid=%d gid=%d",
                                                               pErr, uErr, gErr]}];
            }
            return EINVAL;
        }
    }

    int pipefd[2] = { -1, -1 };
    posix_spawn_file_actions_t actions;
    BOOL useActions = NO;
    spawn_fa_init_fn fa_init = NULL;
    spawn_fa_destroy_fn fa_destroy = NULL;

    if (stdoutOut) {
        fa_init = (spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
        fa_destroy = (spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
        spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
        spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
        if (!fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
            if (attrPtr)
                attr_destroy(attrPtr);
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (errorOut) {
                *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                            userInfo:@{NSLocalizedDescriptionKey : @"posix_spawn_file_actions unavailable"}];
            }
            return -1;
        }
        if (pipe(pipefd) != 0) {
            int e = errno;
            if (attrPtr)
                attr_destroy(attrPtr);
            for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            if (errorOut) {
                *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:e
                                            userInfo:@{NSLocalizedDescriptionKey : @(strerror(e))}];
            }
            return e > 0 ? e : -1;
        }
        fa_init(&actions);
        fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
        fa_dup2(&actions, pipefd[1], STDERR_FILENO);
        fa_close(&actions, pipefd[0]);
        fa_close(&actions, pipefd[1]);
        useActions = YES;
    }

    pid_t pid = 0;
    int spawnErr = spawn(&pid, binaryPath.fileSystemRepresentation,
                         useActions ? &actions : NULL, attrPtr, argv, environ);
    if (attrPtr)
        attr_destroy(attrPtr);

    if (useActions)
        close(pipefd[1]);

    for (NSUInteger i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);

    if (useActions && fa_destroy)
        fa_destroy(&actions);

    if (spawnErr != 0) {
        if (pipefd[0] >= 0)
            close(pipefd[0]);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:spawnErr
                                        userInfo:@{NSLocalizedDescriptionKey :
                                                       [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(spawnErr)]}];
        }
        return spawnErr;
    }

    if (stdoutOut && pipefd[0] >= 0) {
        NSMutableData *data = [NSMutableData data];
        char buf[4096];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
            [data appendBytes:buf length:(NSUInteger)n];
        close(pipefd[0]);
#ifndef DT_BUILD102739J_VARIANT
        if (data.length > 8192)
            data.length = 8192;
#endif
        *stdoutOut = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        int e = errno;
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:e
                                        userInfo:@{NSLocalizedDescriptionKey : @(strerror(e))}];
        }
        return e > 0 ? e : -1;
    }

    if (waitStatusOut)
        *waitStatusOut = status;

    if (exitStatusOut) {
        if (WIFEXITED(status))
            *exitStatusOut = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            *exitStatusOut = 128 + WTERMSIG(status);
        else
            *exitStatusOut = -1;
    }
    return 0;
}

int dt_spawn_root(NSString *binaryPath, NSArray<NSString *> *args, int *exitStatusOut, NSError **errorOut)
{
    return dt_spawn_capture_internal(binaryPath, args, YES, exitStatusOut, NULL, NULL, errorOut);
}

int dt_spawn_root_capture(NSString *binaryPath,
                          NSArray<NSString *> *args,
                          int *exitStatusOut,
                          NSString **stdoutOut,
                          NSError **errorOut)
{
    return dt_spawn_capture_internal(binaryPath, args, YES, exitStatusOut, NULL, stdoutOut, errorOut);
}

int dt_spawn_plain_capture(NSString *binaryPath,
                           NSArray<NSString *> *args,
                           int *exitStatusOut,
                           NSString **stdoutOut,
                           NSError **errorOut)
{
    return dt_spawn_capture_internal(binaryPath, args, NO, exitStatusOut, NULL, stdoutOut, errorOut);
}

int dt_spawn_plain_capture_status(NSString *binaryPath,
                                  NSArray<NSString *> *args,
                                  int *exitStatusOut,
                                  int *waitStatusOut,
                                  NSString **stdoutOut,
                                  NSError **errorOut)
{
    return dt_spawn_capture_internal(binaryPath, args, NO, exitStatusOut, waitStatusOut, stdoutOut, errorOut);
}

int dt_spawn_root_start(NSString *binaryPath,
                        NSArray<NSString *> *args,
                        pid_t *pidOut,
                        NSString **initialStdoutOut,
                        NSError **errorOut)
{
    if (!pidOut) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"pidOut required"}];
        }
        return -1;
    }

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    typedef int (*posix_spawnattr_init_fn)(posix_spawnattr_t *);
    typedef int (*posix_spawnattr_destroy_fn)(posix_spawnattr_t *);
    typedef int (*spawn_fa_init_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
    typedef int (*spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

    void *lib = RTLD_DEFAULT;
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(lib, "posix_spawn");
    posix_spawnattr_init_fn attr_init = (posix_spawnattr_init_fn)dlsym(lib, "posix_spawnattr_init");
    posix_spawnattr_destroy_fn attr_destroy = (posix_spawnattr_destroy_fn)dlsym(lib, "posix_spawnattr_destroy");
    spawn_fa_init_fn fa_init = (spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
    spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
    spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
    spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
    if (!spawn || !attr_init || !attr_destroy || !fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"posix_spawn unavailable"}];
        }
        return -1;
    }

    if (binaryPath.length == 0) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"empty binary path"}];
        }
        return -1;
    }

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:binaryPath.lastPathComponent];
    [argvStrings addObjectsFromArray:args ?: @[]];
    NSUInteger argc = argvStrings.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv)
        return -1;
    for (NSUInteger i = 0; i < argc; i++)
        argv[i] = strdup(argvStrings[i].UTF8String);

    posix_spawnattr_t attr;
    if (attr_init(&attr) != 0) {
        for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        return -1;
    }
    int pErr = posix_spawnattr_set_persona_np(&attr, 99, DT_POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    int uErr = posix_spawnattr_set_persona_uid_np(&attr, 0);
    int gErr = posix_spawnattr_set_persona_gid_np(&attr, 0);
    if (pErr != 0 || uErr != 0 || gErr != 0) {
        attr_destroy(&attr);
        for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:EINVAL
                                        userInfo:@{NSLocalizedDescriptionKey : @"persona attr set failed"}];
        }
        return EINVAL;
    }

    int pipefd[2] = { -1, -1 };
    if (pipe(pipefd) != 0) {
        int e = errno;
        attr_destroy(&attr);
        for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:e
                                        userInfo:@{NSLocalizedDescriptionKey : @(strerror(e))}];
        }
        return e > 0 ? e : -1;
    }

    posix_spawn_file_actions_t actions;
    fa_init(&actions);
    fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    fa_close(&actions, pipefd[0]);
    fa_close(&actions, pipefd[1]);

    pid_t pid = 0;
    int spawnErr = spawn(&pid, binaryPath.fileSystemRepresentation, &actions, &attr, argv, environ);
    attr_destroy(&attr);
    fa_destroy(&actions);
    close(pipefd[1]);

    for (NSUInteger i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);

    if (spawnErr != 0) {
        close(pipefd[0]);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:spawnErr
                                        userInfo:@{NSLocalizedDescriptionKey :
                                                       [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(spawnErr)]}];
        }
        return spawnErr;
    }

    *pidOut = pid;

    if (initialStdoutOut) {
        NSMutableData *data = [NSMutableData data];
        char buf[512];
        const int maxWaitMs = 5000;
        int waitedMs = 0;
        while (waitedMs < maxWaitMs) {
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(pipefd[0], &rfds);
            int sel = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
            if (sel > 0) {
                ssize_t n = read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    [data appendBytes:buf length:(NSUInteger)n];
                    if (data.length >= 4096)
                        break;
                    NSString *partial = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
                    if ([partial rangeOfString:@"helper_pid="].location != NSNotFound)
                        break;
                } else if (n == 0) {
                    break;
                }
            }
            waitedMs += 100;
        }
        close(pipefd[0]);
        if (data.length > 4096)
            data.length = 4096;
        *initialStdoutOut = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    } else {
        close(pipefd[0]);
    }

    return 0;
}

int dt_spawn_plain_start(NSString *binaryPath,
                         NSArray<NSString *> *args,
                         pid_t *pidOut,
                         NSString **initialStdoutOut,
                         NSError **errorOut)
{
    if (!pidOut) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"pidOut required"}];
        }
        return -1;
    }

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    typedef int (*spawn_fa_init_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
    typedef int (*spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

    void *lib = RTLD_DEFAULT;
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(lib, "posix_spawn");
    spawn_fa_init_fn fa_init = (spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
    spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
    spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
    spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
    if (!spawn || !fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"posix_spawn unavailable"}];
        }
        return -1;
    }

    if (binaryPath.length == 0) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"empty binary path"}];
        }
        return -1;
    }

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:binaryPath.lastPathComponent];
    [argvStrings addObjectsFromArray:args ?: @[]];
    NSUInteger argc = argvStrings.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv)
        return -1;
    for (NSUInteger i = 0; i < argc; i++)
        argv[i] = strdup(argvStrings[i].UTF8String);

    int pipefd[2] = { -1, -1 };
    if (pipe(pipefd) != 0) {
        int e = errno;
        for (NSUInteger i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:e
                                        userInfo:@{NSLocalizedDescriptionKey : @(strerror(e))}];
        }
        return e > 0 ? e : -1;
    }

    posix_spawn_file_actions_t actions;
    fa_init(&actions);
    fa_dup2(&actions, pipefd[1], STDOUT_FILENO);
    fa_dup2(&actions, pipefd[1], STDERR_FILENO);
    fa_close(&actions, pipefd[0]);
    fa_close(&actions, pipefd[1]);

    pid_t pid = 0;
    int spawnErr = spawn(&pid, binaryPath.fileSystemRepresentation, &actions, NULL, argv, environ);
    fa_destroy(&actions);
    close(pipefd[1]);

    for (NSUInteger i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);

    if (spawnErr != 0) {
        close(pipefd[0]);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:spawnErr
                                        userInfo:@{NSLocalizedDescriptionKey :
                                                       [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(spawnErr)]}];
        }
        return spawnErr;
    }

    *pidOut = pid;

    if (initialStdoutOut) {
        NSMutableData *data = [NSMutableData data];
        char buf[512];
        const int maxWaitMs = 5000;
        int waitedMs = 0;
        while (waitedMs < maxWaitMs) {
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(pipefd[0], &rfds);
            int sel = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
            if (sel > 0) {
                ssize_t n = read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    [data appendBytes:buf length:(NSUInteger)n];
                    if (data.length >= 4096)
                        break;
                    NSString *partial = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
                    if ([partial rangeOfString:@"helper_pid="].location != NSNotFound)
                        break;
                } else if (n == 0) {
                    break;
                }
            }
            waitedMs += 100;
        }
        close(pipefd[0]);
        if (data.length > 4096)
            data.length = 4096;
        *initialStdoutOut = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    } else {
        close(pipefd[0]);
    }

    return 0;
}

int dt_spawn_hold_probe_start(NSString *binaryPath,
                              pid_t *pidOut,
                              int *stdoutRdOut,
                              int *cmdWrOut,
                              NSString **initialStdoutOut,
                              NSError **errorOut)
{
    if (!pidOut || !stdoutRdOut || !cmdWrOut) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"pidOut/stdoutRdOut/cmdWrOut required"}];
        }
        return -1;
    }

    typedef int (*posix_spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const[], char *const[]);
    typedef int (*spawn_fa_init_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_destroy_fn)(posix_spawn_file_actions_t *);
    typedef int (*spawn_fa_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
    typedef int (*spawn_fa_addclose_fn)(posix_spawn_file_actions_t *, int);

    void *lib = RTLD_DEFAULT;
    posix_spawn_fn spawn = (posix_spawn_fn)dlsym(lib, "posix_spawn");
    spawn_fa_init_fn fa_init = (spawn_fa_init_fn)dlsym(lib, "posix_spawn_file_actions_init");
    spawn_fa_destroy_fn fa_destroy = (spawn_fa_destroy_fn)dlsym(lib, "posix_spawn_file_actions_destroy");
    spawn_fa_adddup2_fn fa_dup2 = (spawn_fa_adddup2_fn)dlsym(lib, "posix_spawn_file_actions_adddup2");
    spawn_fa_addclose_fn fa_close = (spawn_fa_addclose_fn)dlsym(lib, "posix_spawn_file_actions_addclose");
    if (!spawn || !fa_init || !fa_destroy || !fa_dup2 || !fa_close) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"posix_spawn unavailable"}];
        }
        return -1;
    }

    if (binaryPath.length == 0) {
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:1
                                        userInfo:@{NSLocalizedDescriptionKey : @"empty binary path"}];
        }
        return -1;
    }

    int out_pipe[2] = { -1, -1 };
    int cmd_pipe[2] = { -1, -1 };
    if (pipe(out_pipe) != 0 || pipe(cmd_pipe) != 0) {
        int e = errno;
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        if (cmd_pipe[0] >= 0) close(cmd_pipe[0]);
        if (cmd_pipe[1] >= 0) close(cmd_pipe[1]);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:e
                                        userInfo:@{NSLocalizedDescriptionKey : @(strerror(e))}];
        }
        return e > 0 ? e : -1;
    }

    char *argv[] = { (char *)binaryPath.lastPathComponent.UTF8String, (char *)"holdSpawn", NULL };

    const int kCmdTargetFd = kDT633CmdFd;
    NSLog(@"[spawn_root] holdSpawn cmd_pipe[0]=%d cmd_pipe[1]=%d cmd_target_fd=%d",
          cmd_pipe[0], cmd_pipe[1], kCmdTargetFd);

    posix_spawn_file_actions_t actions;
    int fa_r = 0;
    fa_init(&actions);
    fa_r = fa_dup2(&actions, out_pipe[1], STDOUT_FILENO);
    NSLog(@"[spawn_root] fa_dup2(stdout) ret=%d errno=%d", fa_r, fa_r != 0 ? errno : 0);
    fa_r = fa_dup2(&actions, out_pipe[1], STDERR_FILENO);
    NSLog(@"[spawn_root] fa_dup2(stderr) ret=%d errno=%d", fa_r, fa_r != 0 ? errno : 0);
    fa_r = fa_dup2(&actions, cmd_pipe[0], kCmdTargetFd);
    NSLog(@"[spawn_root] fa_dup2(cmd_rd→%d) ret=%d errno=%d", kCmdTargetFd, fa_r, fa_r != 0 ? errno : 0);
    fa_r = fa_close(&actions, out_pipe[0]);
    NSLog(@"[spawn_root] fa_close(out_pipe[0]=%d) ret=%d", out_pipe[0], fa_r);
    fa_r = fa_close(&actions, out_pipe[1]);
    NSLog(@"[spawn_root] fa_close(out_pipe[1]=%d) ret=%d", out_pipe[1], fa_r);
    if (cmd_pipe[0] != kCmdTargetFd) {
        fa_r = fa_close(&actions, cmd_pipe[0]);
        NSLog(@"[spawn_root] fa_close(cmd_pipe[0]=%d) ret=%d", cmd_pipe[0], fa_r);
    } else {
        NSLog(@"[spawn_root] skip fa_close(cmd_pipe[0]) — same as target fd %d", kCmdTargetFd);
    }
    fa_r = fa_close(&actions, cmd_pipe[1]);
    NSLog(@"[spawn_root] fa_close(cmd_pipe[1]=%d) ret=%d", cmd_pipe[1], fa_r);

    pid_t pid = 0;
    int spawnErr = spawn(&pid, binaryPath.fileSystemRepresentation, &actions, NULL, argv, environ);
    fa_destroy(&actions);
    close(out_pipe[1]);
    close(cmd_pipe[0]);

    if (spawnErr != 0) {
        close(out_pipe[0]);
        close(cmd_pipe[1]);
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:@"dt.spawn_root" code:spawnErr
                                        userInfo:@{NSLocalizedDescriptionKey :
                                                       [NSString stringWithFormat:@"posix_spawn failed: %s", strerror(spawnErr)]}];
        }
        return spawnErr;
    }

    *pidOut = pid;
    *stdoutRdOut = out_pipe[0];
    *cmdWrOut = cmd_pipe[1];

    if (initialStdoutOut) {
        NSMutableData *data = [NSMutableData data];
        char buf[512];
        const int maxWaitMs = 5000;
        int waitedMs = 0;
        while (waitedMs < maxWaitMs) {
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(out_pipe[0], &rfds);
            int sel = select(out_pipe[0] + 1, &rfds, NULL, NULL, &tv);
            if (sel > 0) {
                ssize_t n = read(out_pipe[0], buf, sizeof(buf));
                if (n > 0) {
                    [data appendBytes:buf length:(NSUInteger)n];
                    if (data.length >= 4096)
                        break;
                    NSString *partial = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
                    BOOL has_helper = [partial rangeOfString:@"helper_pid="].location != NSNotFound;
                    BOOL has_mode = [partial rangeOfString:@"hold_spawn_mode="].location != NSNotFound;
                    BOOL has_fd_ok = [partial rangeOfString:@"hold_spawn_cmd_fd_ok=1"].location != NSNotFound;
                    BOOL has_fd_bad = [partial rangeOfString:@"hold_spawn_cmd_fd_invalid"].location != NSNotFound;
                    if (has_helper && has_mode && (has_fd_ok || has_fd_bad))
                        break;
                } else if (n == 0) {
                    break;
                }
            }
            waitedMs += 100;
        }
        if (data.length > 4096)
            data.length = 4096;
        *initialStdoutOut = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    }

    return 0;
}
