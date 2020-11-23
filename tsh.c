/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Your Name <andrewid@andrew.cmu.edu>
 * TODO: Include your name and Andrew ID here.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

typedef enum fork_return {
    FORK_ERROR = -1,
    CHILD_PROCESS = 0,
} fork_return;

typedef enum waitpid_return { WAITPID_ERROR = -1 } waitpid_return;
typedef enum fgjob_return { NO_FG_PROCESS = 0 } fgjob_return;

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(EXIT_FAILURE);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(EXIT_FAILURE);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(EXIT_FAILURE);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(EXIT_FAILURE);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(EXIT_FAILURE);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

void output_job_list(const struct cmdline_tokens *token) {
    // block signals
    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    /* Block SIGINT SIGCHILD AND SIGTSP and save previous blocked set */
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    /* Open outfile */
    int fd_outfile;

    if (token->outfile != NULL) {

        if ((fd_outfile = open(token->outfile, O_CREAT | O_WRONLY | O_TRUNC,
                               DEF_MODE)) < 0) {
            perror(token->outfile);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        // output job to outfile
        list_jobs(fd_outfile);

        // close outfile
        if (close(fd_outfile) < 0) {
            perror("close error");
            exit(EXIT_FAILURE);
        }
    } else {

        // output job to stdout
        list_jobs(STDOUT_FILENO);
    }

    /* Restore previous blocked set, unblocking SIGINT SIGCHLD AND
     * SIGTSTP */
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
}

void wait_fg(jid_t jid, pid_t pid, sigset_t prev_mask) {
    if (verbose)
        sio_printf("wait_fg: Waiting for Process (%d) to stop or terminate.\n",
                   pid);

    while (job_exists(jid) && job_get_state(jid) != ST)
        sigsuspend(&prev_mask);
    if (verbose)
        sio_printf("wait_fg: Process (%d) no longer foreground process.\n",
                   pid);
    fflush(stdout);
}

void switch_state(const struct cmdline_tokens *token, job_state state) {
    sigset_t full_mask, prev_mask;

    const int job_index = 1;
    const int argv_min_length = job_index + 1;
    const int jid_offset = 1;
    const char jid_prefix = '%';
    const int jid_prefix_index = 0;

    jid_t jid;
    pid_t pid;

    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    // block sigs
    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);

    if (token->argc < argv_min_length) {
        sio_eprintf("%s command requires PID or %%jobid argument\n",
                    token->argv[0]);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    } else {

        char *job_arg = token->argv[job_index];

        // get jid and pid based on cmdline input
        if (job_arg[jid_prefix_index] == jid_prefix) {

            // ensure the jid is numeric
            if (!isdigit(job_arg[jid_offset])) {
                sio_eprintf("%s: argument must be a PID or %%jobid\n",
                            token->argv[0]);
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return;
            }

            jid = atoi(job_arg + jid_offset);
            if (job_exists(jid)) {
                pid = job_get_pid(jid);
            } else {
                pid = -1;
            }
        } else {

            // ensure the pid is numeric
            if (!isdigit(job_arg[0])) {
                sio_eprintf("%s: argument must be a PID or %%jobid\n",
                            token->argv[0]);
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return;
            }
            pid = atoi(job_arg);
            jid = job_from_pid(pid);
        }

        // ensure job exists
        if (job_exists(jid)) {
            if (job_get_state(jid) == ST) {
                int neg_pid = 0 - pid;

                // pid is negated because we want SIGCONT to be sent to every
                // process in the pg
                kill(neg_pid, SIGCONT);
            }
            job_set_state(jid, state);

        } else {
            sio_eprintf("%s: No such job\n", job_arg);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        if (fg_job() != NO_FG_PROCESS) {
            sio_assert(!sigismember(&prev_mask, SIGCHLD));
            wait_fg(jid, pid, prev_mask);
        } else {
            sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    }
}

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this
 * function (and its helpers) should avoid exiting on error.  This is not to
 * say they shouldn't detect and print (or otherwise handle) errors!
 */
void eval_builtin_command(const struct cmdline_tokens *token) {
    dbg_requires(token->builtin);
    switch (token->builtin) {
    case BUILTIN_NONE:
        return;
    case BUILTIN_QUIT:
        // exit the shell
        exit(EXIT_SUCCESS);
    case BUILTIN_JOBS:
        output_job_list(token);
        return;
    case BUILTIN_BG:
        switch_state(token, BG);
        return;
    case BUILTIN_FG:
        switch_state(token, FG);
        return;
    }
}

void redirect_input(const struct cmdline_tokens *token) {
    int fd_infile, fd_outfile;
    bool open_error = false;

    if (token->infile != NULL) {
        if ((fd_infile = open(token->infile, O_RDONLY)) < 0) {
            perror(token->infile);
            open_error = true;
            exit(EXIT_FAILURE);
        }
        if (!open_error && (dup2(fd_infile, STDIN_FILENO) < 0)) {
            perror("dup2 error infile");
            exit(EXIT_FAILURE);
        }
        if (!open_error && (close(fd_infile) < 0)) {
            perror("close error infile");
            exit(EXIT_FAILURE);
        }
    }

    open_error = false;
    if (token->outfile != NULL) {
        if ((fd_outfile = open(token->outfile, O_CREAT | O_WRONLY | O_TRUNC,
                               DEF_MODE)) < 0) {
            perror(token->outfile);
            open_error = true;
            exit(EXIT_FAILURE);
        }
        if (!open_error && (dup2(fd_outfile, STDOUT_FILENO) < 0)) {
            perror("dup2 error outfile");
            exit(EXIT_FAILURE);
        }
        if (!open_error && close(fd_outfile) < 0) {
            perror("close error outfile");
            exit(EXIT_FAILURE);
        }
    }
}

// void redirect_input(const struct cmdline_tokens *token) {
//     int fd_infile, fd_outfile;

//     // if (token->infile != NULL) {
//     //     if ((fd_infile = open(token->infile, O_RDONLY)) < 0) {
//     //         perror("open error");
//     //         exit(EXIT_FAILURE);
//     //     }
//     //     if (dup2(fd_infile, STDIN_FILENO) < 0) {
//     //         perror("dup2 error");
//     //         exit(EXIT_FAILURE);
//     //     }
//     //     if (close(fd_infile) < 0) {
//     //         perror("close error");
//     //         exit(EXIT_FAILURE);
//     //     }
//     // }

//     if (dup2(fd_outfile, STDOUT_FILENO) < 0) {
//         perror("dup2 error");
//         exit(EXIT_FAILURE);
//     }
// }
// }

// void reset_stdout() {

//     if (dup2(STDIN_FILENO, STDIN_FILENO) < 0) {
//         perror("dup2 error");
//         exit(EXIT_FAILURE);
//     }

//     if (dup2(STDOUT_FILENO, STDOUT_FILENO) < 0) {
//         perror("dup2 error");
//         exit(EXIT_FAILURE);
//     }
//     if (dup2(STDERR_FILENO, STDERR_FILENO) < 0) {
//         perror("dup2 error");
//         exit(EXIT_FAILURE);
//     }
// }

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    jid_t jid;
    sigset_t full_mask, sigchld_full_mask, prev_mask;

    sigemptyset(&full_mask);
    sigemptyset(&sigchld_full_mask);

    // initialize masks
    sigfillset(&full_mask);
    sigaddset(&sigchld_full_mask, SIGCHLD);
    sigaddset(&sigchld_full_mask, SIGINT);
    sigaddset(&sigchld_full_mask, SIGTSTP);
    sigemptyset(&prev_mask);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    // ignore empty lines and parse errors
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        exit(EXIT_FAILURE);
    }

    /** TODO: make helper */
    job_state process_state = UNDEF;
    if (parse_result == PARSELINE_BG) {
        process_state = BG;
    } else if (parse_result == PARSELINE_FG) {
        process_state = FG;
    } else {
        exit(EXIT_FAILURE);
    }

    if (token.builtin != BUILTIN_NONE) {
        eval_builtin_command(&token);
    } else {
        sigprocmask(SIG_BLOCK, &sigchld_full_mask, &prev_mask);
        char **argv = token.argv;
        pid = fork();
        setpgid(0, 0); /** TODO: this seems incorrect */

        if (pid == FORK_ERROR) {
            perror("fork error.");
        } else if (pid == CHILD_PROCESS) { // child runs job
            // redirect infile to STDIN
            fflush(stdout);
            redirect_input(&token);

            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            if (execve(argv[0], argv, environ) < 0) {
                sio_eprintf("%s: No such file or directory\n", argv[0]);
                fflush(stdout);
                exit(EXIT_FAILURE);
            }
            sigprocmask(SIG_BLOCK, &sigchld_full_mask, NULL);
        }

        if (process_state != UNDEF) {
            // block signals before adding to job list
            sigprocmask(SIG_BLOCK, &full_mask, NULL);
            jid = add_job(pid, process_state, cmdline);
        } else {
            if (process_state == UNDEF) {
                sio_eprintf("Shell error: jobstate is undefined.\n");

            } else {
                sio_eprintf("shell_error: Tried to add forground processs when "
                            "one already exists.\n");
            }
            exit(EXIT_FAILURE);
        }
        /* Parent waits for foreground job to terminate if there is one*/
        if (fg_job() != NO_FG_PROCESS) {
            wait_fg(jid, pid, prev_mask);
        } else {
            sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    fflush(stdout);
    // TODO: Implement commands here.
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    if (verbose)
        sio_printf("sigchld_handler: entering\n");

    int olderrno = errno;
    int status;

    sigset_t full_mask, prev_mask;
    sigfillset(&full_mask);

    pid_t pid;
    jid_t jid;

    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG)) > 0) {

        sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);
        if ((jid = job_from_pid(pid)) != 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                delete_job(jid);
                if (verbose) {
                    sio_printf("sigchld_handler: Job [%d] (%d) deleted\n", jid,
                               pid);
                    if (WIFEXITED(status)) {
                        sio_printf("sigchld_handler: Job [%d] (%d) terminated "
                                   "normally (status %d)\n",
                                   jid, pid, WEXITSTATUS(status));
                    }
                }
                if (WIFSIGNALED(status)) {
                    sio_printf("Job [%d] (%d) terminated by signal %d\n", jid,
                               pid, WTERMSIG(status));
                }
            } else if (WIFSTOPPED(status)) {
                sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                           WSTOPSIG(status));
                job_set_state(jid, ST);
            }
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }

    if (pid < 0 && errno != ECHILD) {
        perror("waitpid error. Sigchld handler");
    }

    errno = olderrno;

    if (verbose)
        sio_printf("sigchld_handler: exiting\n");
    fflush(stdout);
}

void sigint_sigtstp_handler(int sig) {
    // for debug output
    char *signal;

    if (sig == SIGINT) {
        signal = "sigint";
    } else if (sig == SIGTSTP) {
        signal = "sigtstp";
    } else {
        signal = "unknown signal";
    }

    sigset_t full_mask, prev_mask;

    sigemptyset(&full_mask);
    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);
    jid_t jid = fg_job();

    if (jid != NO_FG_PROCESS) {
        pid_t pid = job_get_pid(jid);
        pid_t neg_pid = 0 - pid;

        // we are passing in so that kill will send a signal to every
        // process in the pid process group
        kill(neg_pid, sig);
        if (verbose)
            sio_printf("%s_handler: Sent %s to Job [%d] (%d) \n", signal,
                       signal, jid, pid);
    }
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    if (verbose)
        sio_printf("sigint_handler: entering\n");

    sigint_sigtstp_handler(sig);

    if (verbose)
        sio_printf("sigint_handler: Exiting\n");
    errno = olderrno;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    if (verbose)
        sio_printf("sigtstp_handler: entering\n");

    sigint_sigtstp_handler(sig);

    if (verbose)
        sio_printf("sigtstp_handler: Exiting\n");
    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
