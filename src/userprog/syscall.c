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

/* 
	Array of system calls functions.
	System call can be a value from 0 to 12.
	System call max number = 13 

*/
static SYS_WRAPPER system_calls_array[13];

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
  system_calls_array[SYS_HALT] = halt;
  system_calls_array[SYS_EXIT] = exit;
  system_calls_array[SYS_EXEC] = exec;
  system_calls_array[SYS_WAIT] = wait;
  system_calls_array[SYS_CREATE] = create;
  system_calls_array[SYS_REMOVE] = remove;
  system_calls_array[SYS_OPEN] = open;
  system_calls_array[SYS_FILESIZE] = filesize;
  system_calls_array[SYS_READ] = read;
  system_calls_array[SYS_WRITE ] = write;
  system_calls_array[SYS_SEEK] = seek;
  system_calls_array[SYS_TELL] = tell;
  system_calls_array[SYS_CLOSE] = close;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_num;
  SYS_WRAPPER handler;
  bool success = true;

  /* validate stack pointer. */
  if (!validate_user_pointer (f->esp, 4))
    system_exit (-1);

  syscall_num = *((int *)f->esp);

  /* Checks if the system call number in valid range. it should be between 0 and 12*/
  if (syscall_num < 0 || syscall_num >= 13)
    system_exit (-1);

  /* Gets the desired system call handler. */
  handler = system_calls_array[syscall_num];

  /* Runs the system call handler memthod according to syscal number. */
  success = handler (f);
  // check errors
  if (!success)
    system_exit (-1);
}

/*
	Terminates Pintos by calling shutdown_power_off()
*/
static bool halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
  return true;
}
/*
	Terminates the current user program, returning status to the kernel. If the process's parent waits for it
*/
static bool exit (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;
  thread_current ()->terminate_status = *(int *)args;
  thread_exit ();

  return true;
}
/*
Runs the executable whose name is given in cmd_line, 
passing any given arguments, and returns the new process's program id (pid).
*/
static bool exec (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;

  /* Stores the return value. */
  f->eax = process_execute (*(char **)args);

  return true;
}

/*
	Waits for a child process pid and retrieves the child's exit status.
*/
static bool wait (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;

  /* Stores the return value. */
  f->eax = process_wait(*(int *)args);

  return true;
}

/*
Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 
*/
static bool create (struct intr_frame *f)
{
	uint32_t *args = (uint32_t *)(f->esp + 4);

	/* validate the arguments passed by the user process. */
	if (!validate_user_arguments (args, 2))
	return false;
	// TO prevent create null
	if(*(args)==NULL)return false;
	/* Stores the return value. */
	lock_acquire (&file_lock);
	f->eax = filesys_create (*args,  *((unsigned *)(args + 1)));
	lock_release (&file_lock);
	return true;
}
/*
	Deletes the file called file. Returns true if successful, false otherwise
*/
static bool remove (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;

  /* Stores the return value. */
  lock_acquire (&file_lock);
  f->eax = filesys_remove (*(char **)args);
  lock_release (&file_lock);
   

  return true;
}
/*
Opens the file called file. 
Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
*/
static int system_open (const char *file_name)
{
  struct thread *cur = thread_current ();
  struct file *file;
  struct file_directory_entry *f;

  lock_acquire (&file_lock);
  file = filesys_open (file_name);
  lock_release (&file_lock);

  /* Checks if opening file fails. */
  if (file == NULL)
    return FD_ERROR;

  /* Allocates file descriptor entry to pushes into thread OPENED_FILES */
  f = (struct file_directory_entry *)malloc (sizeof (struct file_directory_entry));

  /* Checks if memory allocation fails. */
  if (f == NULL)
    {
      file_close (file);
      return FD_ERROR;
    }

  /* Initialize the entry and pushes it into OPERNED_FILES. */
  f->file = file;
  f->fd = generate_file_discriptor ();
  list_push_back (&cur->opened_files, &f->elem);

  return f->fd;
}

static bool open (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

 	 /* validate the arguments passed by the user process. */
  	if (!validate_user_arguments (args, 1))
    return false;
	//to prevent open null
  	if(*(args)==NULL)return false;
  
 	/* Stores the return value. */
  	f->eax = system_open (*(char **)args);

  	return true;
}

/*
	Returns the size, in bytes, of the file open as fd.
*/
static bool filesize (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;

  /* Stores the return value. */
  struct file_directory_entry *fd;

  /* Gets the file descriptor entry. */
  fd = get_file_discriptor_entry (*(int *)args);

  /* Checks if entry not found or its file. */
  if (fd == NULL || fd->file == NULL)
    return -1;

  lock_acquire (&file_lock);
  f->eax = file_length (fd->file);
  lock_release (&file_lock);


  return true;
}
/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other than end of file).
*/
static int system_read (int fd, void *buffer_, unsigned size)
{
  int result;
  uint8_t *buffer = (uint8_t *)buffer_;
  struct file_directory_entry *f;

  /* case one : Can't read from STDOUT */
  if (fd == STDOUT_FILENO)
    return -1;

  /* case two : special hanlde for STDIN. */
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      for (i = 0; i < size; i++)
  {
    *(buffer + i) = input_getc();
  }
      return size;
    }
    //case Three
  /* Gets the file desriptor entry. */
  f = get_file_discriptor_entry (fd);

  /* Checks if entry not found or its file. */
  if (f == NULL || f->file == NULL)
    return -1;
	
  lock_acquire (&file_lock);
  result = file_read (f->file, buffer, size);
  lock_release (&file_lock);

  return result;
}

static bool read (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 3))
    return false;

  void *buffer = *(args + 1);
  uint32_t size = *(args + 2);

  /* validate if the buffer block valid. */
  if (!validate_user_pointer (buffer, size))
    return false;

  /* Stores the return value. */
  f->eax = system_read (*(int*)args, buffer, size);

  return true;
}
/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, 
which may be less than size if some bytes could not be written.
*/
static int system_write (int fd, void *buffer_, unsigned size)
{
  int result;
  uint8_t *buffer = (uint8_t *)buffer_;
  struct file_directory_entry *f;

  /* case 1 : Can't write to STDIN. */
  if (fd == STDIN_FILENO)
    return -1;

  /* case 2 : Special handle for STDOUT. */
  if (fd == STDOUT_FILENO)
    {
      putbuf((char *)buffer, size);
      return (int)size;
    }
    //case 3 :
  /* Gets the file descriptor entry. */
  f = get_file_discriptor_entry (fd);

  /* Checks if entry not found or its file. */
  if (f == NULL || f->file == NULL)
    return -1;

  lock_acquire (&file_lock);
  result = file_write (f->file, buffer, size);
  lock_release (&file_lock);

  return result;
}

static bool write (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 3))
    return false;

  void *buffer = *(args + 1);
  uint32_t size = *(args + 2);

  /* validate if the buffer block valid. */
  if (!validate_user_pointer (buffer, size))
    return false;

  /* Stores the return value. */
  f->eax = system_write (*(int*)args, buffer, size);
  return true;
}
/*
	Changes the next byte to be read or written in open file fd to position, 
	expressed in bytes from the beginning of the file.
*/
static bool seek (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);
  unsigned position;
  int fd;
  struct file_directory_entry *fn;

  /* validate  the arguments passed by the user process. */
  if (!validate_user_arguments (args, 2))
    return false;

  /* Set the position from the second argument. */
  position = *(unsigned *)(args + 1);

  /* check position, Position must be non negative. */
  if ((int)position < 0)
    return false;

  fd = *(int *)args;

  /* Gets the file descriptor entry. */
  fn = get_file_discriptor_entry (fd);

  /* Checks if entry not found or its file. */
  if (fn == NULL || fn->file == NULL)
    return false;

  

  struct file_directory_entry *temp_fd;

  /* Gets the file descriptor entry. */
  temp_fd = get_file_discriptor_entry (fd);

  lock_acquire (&file_lock);
  file_seek (temp_fd->file, position);
  lock_release (&file_lock);

  return true;
}
/*
	Returns the position of the next byte to be read or written in open file fd,
	 expressed in bytes from the beginning of the file.
*/
static unsigned sys_tell (int fd)
{
  struct file_directory_entry *f;
  unsigned result;

  /* Gets the file descriptor entry. */
  f = get_file_discriptor_entry (fd);

  /* Checks if entry not found or its file. then generate error */
  if (f == NULL || f->file == NULL)
    return -1;
	// valid file
  lock_acquire (&file_lock);
  result = file_tell (f->file);
  lock_release (&file_lock);

  return result;
}


static bool tell (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;

  /* Stores the return value. */
  f->eax = sys_tell (*(int *)args);

  return true;
}

/*
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its 
open file descriptors, as if by calling this function for each one.

*/
static bool close (struct intr_frame *f)
{
  uint32_t *args = (uint32_t *)(f->esp + 4);

  /* validate the arguments passed by the user process. */
  if (!validate_user_arguments (args, 1))
    return false;
  struct file_directory_entry *fd = get_file_discriptor_entry (*(int *)args);
  /* Checks if entry not found. */
  if (fd == NULL)
    return;
  fd_close (fd);
  return true;
}


/*******************************************Additional Maethods By Ahmed Eid*********************************************/
/*
	 Checks all the arguments ARGS sent by the user process. 
	 Parameters : args
	 Return true in case of all parameters are valid and false otherwise.

*/

static bool validate_user_arguments (const uint32_t *args, size_t argc)
{
	return ( !validate_user_pointer (args + argc , 4)) ?false :true ;
}
/* 
	Checks the pointer passed by the user process.
	Parameters : pointer, size in bytes
   	Returns :true if valid, or false otherwise. 

*/

static bool validate_user_pointer (const void *usr_ptr, unsigned bytes)
{
    return read_byte((uint8_t *)usr_ptr + bytes) ==-1 ? false:true;
}

/* 	Reads a byte at user virtual address ADDR. and check if it is in user space 
	Parameters : addr
   	Returns the byte value if successful, -1 if a segfault happened. 

 */

static int read_byte (const uint8_t *addr)
{
  if(!is_user_vaddr(addr))
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*addr));

  return result;
}

/* 
	Returns a file descriptor to use for a file. 
	Parameters : void
	Return filediscriptor
*/
static fd_t generate_file_discriptor (void)
{
  static fd_t next_file_descriptor = 2;
  return next_file_descriptor++;
}


/*
	 Gets the file descriptor entry whose fd = FILE_FD
  	 Returns the fd_entry, or NULL if not exist.

*/
static struct file_directory_entry* get_file_discriptor_entry (fd_t file_fd)
{
  struct list_elem *e;

  struct thread *cur = thread_current ();

  for (e = list_begin (&cur->opened_files); e != list_end (&cur->opened_files);
       e = list_next (e))
    {
      struct file_directory_entry *f = list_entry (e, struct file_directory_entry, elem);
      if (f->fd == file_fd)
  return f;
    }

  return NULL;
}
/*
	Exit from current process
	Parameters : status
	Void return method
*/
static void system_exit (int status)
{
  /* Saves the exit status and terminates the thread. */
  thread_current ()->terminate_status = status;
  thread_exit ();
}