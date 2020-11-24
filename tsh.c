/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * This sell is a command line interpreter that runs programs. The shell prints
 * a prompt and waits for a command line from the user. Then carries out the
 * action specified by the command line.
 *
 * The command line contains one or more words. The first one is the name of the
 * action that the shell should perform. This can be the path to a program or a
 * built in command. The words following are the arguments to be passed into the
 * command.
 *
 * Built in processes implemented by the shell
 *      quit        : quits the shell
 *      job         : prints out the job list
 *      fg (job)    : switches the state of a job to the foreground
 *      bg (job)    : switches the state of a job to the background
 *
 * For fg and bg, job can be either the job id (jid) or the process id (pid) of
 * the job. The job id is passed with an '%' to indicate that the job identifier
 * is a job id not a process id.
 *
 * The job ids and process ids of each job is specified in it's
 * job list entry which is formatted as follows:
 *
 *              [jid] (pid) command_line
 *
 * This shell supports forground and background processes. Background processes
 * are specified by terminating the command line with an '&'. To run a
 * foreground process, the command line is not terminated with a special
 * character. The shell waits for foreground processes to terminate and be
 * reaped by the SIGCHLD handler using sigsuspend and waitpid before resuming
 * execution and printing the next shell prompt.
 *
 * This shell implements 3 handlers:
 *      sigint  Handles Ctrl-C
 *      sigtstp Handles Ctrl-Z
 *      sigchld Handles stopped or terminated child processes
 *
 *
 * IO Redirection
 * The shell can read input from a file using the '< input file' after the
 * command. It redirects stdin to the input file. The shell can redirect output
 * to a file using the '> input file' after the command. It redirects stdout to
 * the output file.
 *
 * @author Austin Lin <andrewid@andrew.cmu.edu>
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

/* Defines enums for the return values of various functions */
typedef enum fork_return { CHILD_PROCESS = 0 } fork_return;
typedef enum function_return { ERROR = -1, SUCCESS = 1 } function_return;
typedef enum fgjob_return { NO_FG_PROCESS = 0 } fgjob_return;

/**
 * @brief initiates the shell's data structures and drives the shell's read and
 * eval loop
 *
 * Sets STDERR to STDOUT and sets STDOUT to line buffering. Parses the cmdline
 * to determine verbosity of the output. Sets the environment variable.
 * initiates the job list. Installs signal handlers and starts the shell's read
 * and eval loop.
 *
 *
 * @param[in] argc The number of cmdline args
 * @param[in] argv A pointer to an array of cmdline arguments
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
 * @brief outputs the job list to outfile if specfied or stdout if outfile is
 * not specified
 *
 * param[in] token A pointer to a cmdline_tokens struct containing the path of
 * the  outfile
 *
 */
void output_job_list(const struct cmdline_tokens *token) {

    sigset_t mask, prev_mask;
    int fd_outfile;

    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    /* Block SIGINT SIGCHILD AND SIGTSP and save previous blocked set */
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    if (token->outfile != NULL) {

        // outfile is specfied so create or open outfile, truncate, and write
        // job list to it
        if ((fd_outfile = open(token->outfile, O_CREAT | O_WRONLY | O_TRUNC,
                               DEF_MODE)) < 0) {
            perror(token->outfile);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }
        list_jobs(fd_outfile);
        if (close(fd_outfile) < 0) {
            perror("close error");
            exit(EXIT_FAILURE);
        }

    } else { // outfile not specified -> output job to stdout
        list_jobs(STDOUT_FILENO);
    }

    /* unblock SIGINT SIGCHLD AND SIGTSTP */
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
}

/**
 * @brief waits for the foreground process to terminate using sigsuspend
 *
 * @param[in] jid The jid of the fg process
 * @param[in] pid The pid of the process to be
 * @param[in] prev_mask a mask where SIGCHLD signals are not blocked
 *
 * @pre all signals are blocked prior to calling
 * @pre SIGCHLD signals are not blocked in prev_mask
 * @pre the specified job is the foreground job
 */
void wait_fg(jid_t jid, pid_t pid, sigset_t prev_mask) {

    sio_assert(!sigismember(&prev_mask, SIGCHLD));
    sio_assert(fg_job() == jid);

    if (verbose)
        sio_printf("wait_fg: Waiting for Process (%d) to stop or terminate.\n",
                   pid);

    // wait until fg job has terminated
    while (fg_job() == jid)
        sigsuspend(&prev_mask);
    if (verbose)
        sio_printf("wait_fg: Process (%d) no longer foreground process.\n",
                   pid);
}

/**
 * @brief parses the command line for the pid or jid then sets the value that
 * pid and jid point to to the pid and jid of the job
 *
 * If the job is prefixed with a '%', it is a jid. The jid is parsed and the pid
 * is determined from the jid.
 *
 * If the job is just a number, it is a pid, and the pid is parsed and the jid
 * is determined from the pid.
 *
 * @param[in] token A pointer to a cmdline_tokens struct containing the command
 * line
 * @param[out] pid A pointer pointing to the pid
 * @param[out] jid A pointer pointing to the jid
 *
 * @return -1 if the job was not found or input was not correct
 * @return 0 if the pid and jid were successfully found
 *
 */
int cmdline_get_pid_jid(const struct cmdline_tokens *token, pid_t *pid,
                        jid_t *jid) {

    const int job_index = 1;  // index of the job in argv
    const int jid_offset = 1; // index of the start of the jid after the prefix
    const char jid_prefix = '%';    // the prefix denoting that a jid was passed
    const int jid_prefix_index = 0; /* index of the start of the
                                       pid after the prefix */

    enum { JOB_NOT_FOUND = -1 };

    char *job_arg = token->argv[job_index];

    // jid was passed on the cmdline
    if (job_arg[jid_prefix_index] == jid_prefix) {

        // ensure the jid is numeric
        if (!isdigit(job_arg[jid_offset])) {
            sio_eprintf("%s: argument must be a PID or %%jobid\n",
                        token->argv[0]);
            return ERROR;
        }

        // get jid and pid
        *jid = atoi(job_arg + jid_offset);
        if (job_exists(*jid)) {
            *pid = job_get_pid(*jid);

        } else { // job not in job list
            *pid = JOB_NOT_FOUND;
        }
    }

    // pid was passed on the cmdline
    else {
        // ensure the pid is numeric
        if (!isdigit(job_arg[0])) {
            sio_eprintf("%s: argument must be a PID or %%jobid\n",
                        token->argv[0]);
            return ERROR;
        }

        // parse pid and jid
        *pid = atoi(job_arg);
        *jid = job_from_pid(*pid);
    }
    return SUCCESS;
}

/**
 * @brief resets the state of a job after the job has started executing
 *
 * Parses the cmd line for the job. Then determines whether the job is a jid or
 * pid. A jid is prefaced with a '%' on the cmd line. A pid is just a number.
 * Then determines the other id from the id that was passed on the cmd line. The
 * job state is updated in the job list. If the specified job became a
 * foreground job, the function waits for it to terminate before returning.
 *
 * @param[in] tokens A pointer to a cmdline_tokens struct containing the cmd
 * line args
 * @param[in] state The state that the job is changing to
 *
 */
void switch_state(const struct cmdline_tokens *token, job_state state) {
    sigset_t full_mask, prev_mask;

    const int job_index = 1;                   // index of the job in argv
    const int argv_min_length = job_index + 1; // minimum length of argv
                                               // if it contains a pid or jid

    jid_t jid;
    pid_t pid;

    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    // block signals before accessing job list
    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);

    // cmdline does not have state and job based on length of argv
    if (token->argc < argv_min_length) {
        sio_eprintf("%s command requires PID or %%jobid argument\n",
                    token->argv[0]);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    }

    // command line has minimum number arguments to contain state and job
    else {
        char *job_arg = token->argv[job_index];

        // parse job (pid and jid) from cmdline
        if (cmdline_get_pid_jid(token, &pid, &jid) == ERROR) {
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        // job exists
        if (job_exists(jid)) {
            if (job_get_state(jid) == ST) {
                int neg_pid = 0 - pid;

                // pid is negated because we want SIGCONT to be sent to every
                // process in the process group
                kill(neg_pid, SIGCONT);
            }

            // set the state of the job to the new state
            job_set_state(jid, state);
        }

        // job doesn't exist
        else {
            sio_eprintf("%s: No such job\n", job_arg);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        // wait for foreground processs to terminate if the specified job was
        // changed to a fg job
        if (fg_job() != NO_FG_PROCESS) {
            sio_assert(!sigismember(&prev_mask, SIGCHLD));
            wait_fg(jid, pid, prev_mask);
        }

        // specified job was not a fg job so print joblist entry
        else {
            sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    }
}

/**
 * @brief Evaluates built in commands: quit, job, bg, and fg
 *
 * quit: quits the shell
 * job: prints out the job list
 * fg: switches the state of a job to the foreground
 * bg: switches the state of a job to the background
 *
 * @param[in] token A pointer to a cmdline_tokens struct
 *                  containing the builtin type
 *
 */
void eval_builtin_command(const struct cmdline_tokens *token) {
    dbg_requires(token->builtin);
    switch (token->builtin) {

    case BUILTIN_NONE:
        break;

    case BUILTIN_QUIT:
        exit(EXIT_SUCCESS);

    case BUILTIN_JOBS:
        output_job_list(token);
        break;

    case BUILTIN_BG:
        switch_state(token, BG);
        break;

    case BUILTIN_FG:
        switch_state(token, FG);
        break;
    }
}

/**
 * @brief Redirects infile to STDIN and STDOUT to outfile if specified on the
 * command line
 *
 * If outfile does not exist, it is created. If outfile exists it is truncated
 * so that the file is entirely overwritten
 *
 * @param[in] token  A pointer to a cmdline_tokens struct containing the paths
 * of the infile and the outfile
 *
 */
void redirect_IO(const struct cmdline_tokens *token) {

    int fd_infile, fd_outfile;
    bool open_error = false;

    // redirect infile to STDIN
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

    // redirect outfile to STDOUT
    open_error = false;
    if (token->outfile != NULL) {

        // if outfile doesn't exist, it is created
        // if outfile exists it is truncated so it is entirely overwritten
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

/** @brief gets the state of a job after parsing the command line
 *
 * @param[in] parse_result The enum returned after parsing the command line
 *
 * @return the state of the job as a job_state enum
 */
job_state state_from_parseline(parseline_return parse_result) {
    job_state process_state = UNDEF;
    if (parse_result == PARSELINE_BG) {
        process_state = BG;
    } else if (parse_result == PARSELINE_FG) {
        process_state = FG;
    } else {
        exit(EXIT_FAILURE);
    }
    return process_state;
}

/**
 * @brief parses and runs the command line
 *
 * Parses the cmdline. Built in processes are executed by the parent. If the job
 * is not a builtin, the parent is forked and the job is added to the job list
 * and executed by the child. If the job is a foreground process, the eval
 * function waits for the child to terminate and be reaped before resuming
 * execution.
 *
 * If an input file is specified, the file is opened and stdin is redirected to
 * point to the file contents.
 *
 * If an output file is specified, the file is opened and truncated or created
 * and stdout is redirected to point to the file contents
 *
 * @param[in] cmdline The string passed into the command line
 *
 */
void eval(const char *cmdline) {

    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    jid_t jid;
    sigset_t full_mask, sigchld_sigint_sigtstp_mask, prev_mask;
    char **argv;

    // initialize masks
    sigemptyset(&full_mask);
    sigemptyset(&sigchld_sigint_sigtstp_mask);
    sigemptyset(&prev_mask);
    sigfillset(&full_mask);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGCHLD);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGINT);
    sigaddset(&sigchld_sigint_sigtstp_mask, SIGTSTP);

    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        exit(EXIT_FAILURE);
    }

    // get job state from parse_result
    job_state process_state = UNDEF;
    process_state = state_from_parseline(parse_result);

    if (token.builtin != BUILTIN_NONE) {
        eval_builtin_command(&token);
    } else {
        argv = token.argv;

        // block signals to prevent the child terminating before the parent can
        // add the child to the job list
        sigprocmask(SIG_BLOCK, &sigchld_sigint_sigtstp_mask, &prev_mask);

        // create child process and place all children in their a new
        // process group separate from the shell
        pid = fork();
        setpgid(0, 0);

        if (pid == ERROR) {
            perror("fork error.");
        } else if (pid == CHILD_PROCESS) {

            // redirect infile to STDIN and outfile to STDOUT
            redirect_IO(&token);

            // unblock signals before execve so child does not inherit masks
            // from parent
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            // execute child process
            if (execve(argv[0], argv, environ) < 0) {
                if (access(argv[0], R_OK) < 0) {
                    perror(argv[0]);
                }
                exit(EXIT_FAILURE);
            }
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
        } else { // print job list entry
            sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
}

/**
 * @brief prints the status of each child reaped or stopped by wait pid
 *
 * @param[in] status Integer represenation of the status returned by waitpid
 * @param[in] jid  Job ID of the job
 * @param[in] pid  process group id of the job
 *
 */
void print_sigchld_status(int status, jid_t jid, pid_t pid) {

    // if job terminated normally, only print if verbose mode is specified
    if (verbose && WIFEXITED(status)) {

        sio_printf("sigchld_handler: Job [%d] (%d) deleted\n", jid, pid);
        sio_printf("sigchld_handler: Job [%d] (%d) terminated "
                   "normally (status %d)\n",
                   jid, pid, WEXITSTATUS(status));
    }

    // job was terminated by signal
    else if (WIFSIGNALED(status)) {

        sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                   WTERMSIG(status));
    }

    // job was stopped by signal
    else if (WIFSTOPPED(status)) {

        sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                   WSTOPSIG(status));
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Reaps child processes when child is stopped or terminated
 *
 * When a SIGCHLD is recieved, the handler reaps as many children as it is able
 * to because SIGCHLD signals can coalesce. To prevent execution of the signal
 * handler from being interupted all signals are blocked inside the handler.
 *
 * If the child process is terminated normally, the process is removed from the
 * job list. If the child is terminated by a signal, the process is removed from
 * the job list and the signal that stopped the child is printed to the shell.
 * If the child is terminated by a signal, the process is removed from the job
 * list and the signal that stopped the child is printed to the shell. If the
 * child is stopped by a signal, the state of the process is set to stopped in
 * the job list and and the signal that stopped the child is printed to the
 * shell.
 *
 * @param[in] sig - The signal that is being passed into the signal handler
 *
 * @remark all signals are blocked inside handler
 * @remark saves and restores errno
 */
void sigchld_handler(int sig) {

    sigset_t full_mask, prev_mask;
    int olderrno, status;
    pid_t pid;
    jid_t jid;

    if (verbose)
        sio_printf("sigchld_handler: entering\n");

    // save errno to restore on exit
    olderrno = errno;

    // initialize signal blocking masks
    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    // block signals inside handler to prevent interuption of execution
    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);

    // reap as many children as possible since signals can coalesce
    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG)) > 0) {

        jid = job_from_pid(pid);
        if (job_exists(jid)) {

            // job terminated normally or by signal
            if (WIFEXITED(status) || WIFSIGNALED(status)) {

                delete_job(jid);
                print_sigchld_status(status, jid, pid);
            }

            // job stopped by signal
            else if (WIFSTOPPED(status)) {

                job_set_state(jid, ST);
                print_sigchld_status(status, jid, pid);
            }
        }
    }

    // check for errors with waitpid
    if (pid == ERROR && errno != ECHILD) {
        perror("waitpid error. Sigchld handler");
    }

    // unblock signals before exiting
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    // restore ernno
    errno = olderrno;

    if (verbose)
        sio_printf("sigchld_handler: exiting\n");
}

/**
 * @brief Sends SIGINT or SIGTSTP signal to all processes in the forground
 * process when there is an interupt or stop command from the keyboard.
 *
 * The handler for both of these signals is basically the same. The only
 * difference is the signal that is being sent to the child processes in the
 * foreground process group. When an interupt is recieved a SIGINT is sent to
 * the child processes and when a stop is received a SIGTSTP is sent to the
 * child processes in the fg process group using kill().
 *
 * @param[in] sig  The numerical number of the signal being handled
 * @param[in] signal  String represenation of the signal being handled for
 * debugging messages
 *
 * @pre sig is SIGINT or SIGTSTP
 * @remark All signals are blocked inside of the handler
 * @remark saves and restores errno
 *
 */
void sigint_sigtstp_handler(int sig, char *signal) {

    sigset_t full_mask, prev_mask;
    jid_t jid;
    pid_t pid, neg_pid;

    // save errno to restore on exit
    int olderrno = errno;

    // This handler should only process SIGING and SIGTSTP signals
    sio_assert(sig == SIGINT || sig == SIGTSTP);

    // initialize blocking masks
    sigemptyset(&full_mask);
    sigfillset(&full_mask);
    sigemptyset(&prev_mask);

    // block all signals before manpulating/accessing the job list
    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);

    // ensure there is a foreground job and it has not terminated
    jid = fg_job();
    if (job_exists(jid)) {

        // get foreground process process group
        pid = job_get_pid(jid);
        neg_pid = 0 - pid;

        // we are passing in negpid so that kill will send the specified signal
        // to every process in the same process group as pid
        if (kill(neg_pid, sig) == ERROR) {
            perror("kill() error.");
        }

        if (verbose)
            sio_printf("%s_handler: Sent %s to Job [%d] (%d) \n", signal,
                       signal, jid, pid);
    }

    // restore masks before exiting
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    // save errno to restore on exit
    errno = olderrno;
}

/**
 * @brief Wrapper function for sigint_sigtstp_handler in order to pass string
 * representation of SIGINT signal for debugging purposes
 *
 * called when there is a interrupt command from the keyboard
 *
 * @param[in] sig ID of SIGINT signal
 * @remark saves and restores errno
 */
void sigint_handler(int sig) {

    // save errno
    int olderrno = errno;

    if (verbose)
        sio_printf("sigint_handler: entering\n");

    // call handler
    sigint_sigtstp_handler(sig, "sigint");

    if (verbose)
        sio_printf("sigint_handler: Exiting\n");

    // restore errno
    errno = olderrno;
}

/**
 * @brief Wrapper function for sigint_sigtstp_handler in order to pass string
 * representation of SIGTSTP signal for debugging purposes.
 *
 * called when there is a stop command from the keyboard
 *
 * @param[in] sig ID of SIGTSTP signal
 * @remark saves and restores errno
 */
void sigtstp_handler(int sig) {

    // save errno to restore on exit
    int olderrno = errno;

    if (verbose)
        sio_printf("sigtstp_handler: entering\n");

    // call real handler
    sigint_sigtstp_handler(sig, "sigtstp");

    if (verbose)
        sio_printf("sigtstp_handler: Exiting\n");

    // restore old errno
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
