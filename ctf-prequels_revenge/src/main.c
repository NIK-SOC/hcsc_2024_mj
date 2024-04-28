#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <seccomp.h>


#define MAX_NAME_LENGTH 50
const char *version = "102";
scmp_filter_ctx ctx;

void init_buffering()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig)
{
    if (sig == SIGALRM)
    {
        printf("[!] Anti DoS Signal. Patch me out for testing.");
        _exit(0);
    }
}

void ignore_me_init_signal()
{
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}

void disable_exec_syscall() {
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_load(ctx);
}

void get_message(char *sql, char *name) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open("messages.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    rc = sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind text: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        printf("%s\n", sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

int read_name(char *name) {
    printf("Enter your name: \n");
    gets(name);
}

void print_version() {
    printf("Prequel's Revenge v%c.%c.%c\n", version[0], version[1], version[2]);
}

int main() {
    char name[MAX_NAME_LENGTH];

    ignore_me_init_signal();
    init_buffering();
    disable_exec_syscall();
    print_version();

    read_name(name);

    printf("Fetching your message...\n");
    get_message("SELECT message FROM messages WHERE name=?;", name);

    seccomp_release(ctx);
    return 0;
}

void mary_poppins() {
    asm("pop %rdi; ret;");
    asm("pop %rsi; ret;");
}