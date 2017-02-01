#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
typedef int fd_t;
#define FD_ERROR ((fd_t) -1)
#include "threads/thread.h"
struct lock file_lock;

//struct fd_entry
struct file_directory_entry
{
  struct file *file;      
  fd_t fd;			          
  struct list_elem elem;
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
