#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"


typedef bool (*SYS_WRAPPER) (struct intr_frame *);

void syscall_init (void);
static bool halt (struct intr_frame *);
static bool exit (struct intr_frame *);
static bool exec (struct intr_frame *);
static bool wait (struct intr_frame *);
static bool create (struct intr_frame *);
static bool remove (struct intr_frame *);
static bool open (struct intr_frame *);
static bool filesize (struct intr_frame *);
static bool read(struct intr_frame *);
static bool write (struct intr_frame *);
static bool seek (struct intr_frame *);
static bool tell (struct intr_frame *);
static bool close (struct intr_frame *);


static void system_exit (int status);
static bool validate_user_pointer (const void *usr_ptr, unsigned bytes);
static bool validate_user_arguments (const uint32_t *args, size_t argc);
static fd_t generate_file_discriptor (void);
static int read_byte (const uint8_t *addr);
static struct file_directory_entry* get_file_discriptor_entry (fd_t file_fd);

static void syscall_handler (struct intr_frame *);



#endif /* userprog/syscall.h */
