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
typedef enum fgjob_return { NO_FG_PROCESS = -1 } fgjob_return;

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

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
bool eval_builtin_command(const struct cmdline_tokens *token) {
    dbg_requires(token->builtin);
    if (token->builtin == BUILTIN_QUIT) {
        fflush(stdout);
        // exit the shell
        exit(EXIT_SUCCESS);
    }
    if (token->builtin == BUILTIN_JOBS) {

        // block signals
        __sigset_t mask, prev_mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGCHLD);
        sigaddset(&mask, SIGTSTP);

        /* Block SIGINT SIGCHILD AND SIGTSP and save previous blocked set */
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        // output job to stdout
        list_jobs(STDOUT_FILENO);

        /* Restore previous blocked set, unblocking SIGINT SIGCHLD AND
         * SIGTSTP */
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    return 1;
}

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
    __sigset_t full_mask, sigchld_sigint_sigtstp_mask, prev_mask;

    sigemptyset(&full_mask);
    sigemptyset(&sigchld_sigint_sigtstp_mask);

    // initialize masks
    sigfillset(&full_mask);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGCHLD);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGINT);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGTSTP);
    sigemptyset(&prev_mask);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    // ignore empty lines and parse errors
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        fflush(stdout);
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
    } else { // evaluate builtin

        sigprocmask(SIG_BLOCK, &sigchld_sigint_sigtstp_mask, &prev_mask);
        char **argv = token.argv;
        if ((pid = fork()) == FORK_ERROR) {
            perror("fork error.");
        } else if (pid == CHILD_PROCESS) { // child runs job
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            setpgid(0, 0);
            if (execve(argv[0], argv, environ) < 0) {
                sio_eprintf("%s: No such file or directory\n", argv[0]);
                fflush(stdout);
                exit(EXIT_FAILURE);
            }
            sigprocmask(SIG_BLOCK, &sigchld_sigint_sigtstp_mask, NULL);
        }

        if (process_state != UNDEF) {
            // block signals before adding to job list
            sigprocmask(SIG_BLOCK, &full_mask, NULL);
            jid = add_job(pid, process_state, cmdline);
        } else {
            if (process_state == UNDEF) {
                sio_eprintf("Shell error: jobstate is undefined.");

            } else {
                sio_eprintf("shell_error: Tried to add forground processs when "
                            "one already exists.\n");
            }
            exit(EXIT_FAILURE);
        }

        /* Parent waits for foreground job to terminate */
        if (parse_result != PARSELINE_BG) {
            while (job_exists(jid) && job_get_state(jid) != ST)
                sigsuspend(&prev_mask);
            fflush(stdout);
            if (verbose)
                sio_printf("Process (%d) no longer foreground process.\n", pid);

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
        sio_printf("SIGCHLD_Handler: Entering\n");

    int olderrno = errno;
    int status;

    __sigset_t full_mask, prev_mask;
    sigfillset(&full_mask);

    pid_t pid;
    jid_t jid;

    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG)) > 0) {

        sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);
        if ((jid = job_from_pid(pid)) != 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                delete_job(jid);
                if (verbose) {
                    sio_printf("SIGCHLD_Handler: Job [%d] (%d) deleted\n", jid,
                               pid);
                    if (WIFEXITED(status)) {
                        sio_printf("SIGCHLD_Handler: Job [%d] (%d) terminated "
                                   "normally\n",
                                   jid, pid);
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
        sio_printf("SIGCHLD_Handler: Exiting\n");
    fflush(stdout);
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {
    if (verbose)
        sio_printf("sigint_handler: Entering\n");

    int olderrno = errno;
    __sigset_t full_mask, prev_mask;

    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);
    jid_t jid = fg_job();

    if (jid > 0) {
        pid_t pid = job_get_pid(jid);
        kill(pid, SIGINT);
        if (verbose)
            sio_printf("sigint_handler: Sent SIGINT to Job [%d] (%d) \n", jid,
                       pid);
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

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
    if (verbose)
        sio_printf("sigtstp_handler: Entering\n");
    int olderrno = errno;

    __sigset_t full_mask, prev_mask;

    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);
    jid_t jid = fg_job();

    if (jid > 0) {
        pid_t pid = job_get_pid(jid);
        kill(pid, SIGTSTP);
        if (verbose)
            sio_printf("sigtstp_handler: Sent SIGTSTP to Job [%d] (%d) \n", jid,
                       pid);
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

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
