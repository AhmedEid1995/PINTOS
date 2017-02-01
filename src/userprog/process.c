#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static char *get_file_name (const char *cmdline);
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct thread_child *current_thread_get_child (pid_t pid);
static void remove_child (struct thread_child *child);
static void thread_remove_children (void);
static void close_all_files (void);
void fd_close (struct file_directory_entry *f);
static void setup_stack_args (void **esp, char *file_name, char **save_ptr);


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *fn_copy;
  char *file_name;
  tid_t child_tid;
  struct thread_child *child;
 
  	
  int load_msg;

  /* Make a copy of CMDLINE.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmdline, PGSIZE);

  file_name = get_file_name (cmdline);

  if (file_name == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  /* Allocate the child represent this process
     to push into the parent CHILD_LIST. */
    child = malloc (sizeof (struct thread_child));

  if (child == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  /* Create a new thread to execute FILE_NAME. */
    child_tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);


    if (child_tid == TID_ERROR)
      palloc_free_page (fn_copy);


  free (file_name);

  /*itialize a thread_child object for the new created thread
	and wakes the child thread to continue it's creation
  */

  struct thread *t;
  child->tid = child_tid;
  t = thread_get (child_tid);
  sema_init (&child->semaphore_object.sema, 0);
  t->semaphore_object = &(child->semaphore_object);
  sema_up (&t->thread_ready);

  /*waits for a message from threads child to see if it's created correctly or not*/
  sema_down (&child->semaphore_object.sema);
  load_msg = child->semaphore_object.has_error;
  



  /* Checks if the child fails in loading the executable. */
  if (load_msg == -1)
    {
      free (child);
      return TID_ERROR;
    }

  /*add the child to child list of its parent*/
  list_push_back (&thread_current ()->child_list, &child->elem);
  return child_tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmdline_)
{
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current ();

  char *token_, *esp_;    			//Used for adding the the args to the stack
  char *token, *save_ptr;			//Used in the string splitting
  int i;							//For the loop
  char* addrs[100];					//Used to save the addresses of the arguments in the stack
  int num_of_args = 0;				//Save number of arguments
  char *full_arg = malloc(strlen(cmdline_) + 1);	//To save the full cmd line to cut it, save place in memory for it
  strlcpy(full_arg, cmdline_, strlen(cmdline_) + 1);	//Copy cmd line into full_arg
  int full_length = 0;				//For the allignment

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmdline_, &if_.eip, &if_.esp);

  if(success){
  	if(strlen(cmdline_) > PGSIZE){
  		success = false;
  	}
  }

  if(success){
  	/* A loop on the arguments to cut the full argument into separate srtings, copy the arguments to the stack, edit the esp pointer,
  	   save the addresses of the arguments in the addrs array and increment num_of_arguments */
	for(token = strtok_r(full_arg, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
	{
		//Decrease the pointer by the length of the argument plus 1 for the '\0'
		if_.esp -= (strlen(token) + 1);
		//Add the address to the addrs array and increment the num_of_argumetns
		addrs[num_of_args++] = (char *)if_.esp; 
		//Make esp point tp the same as interupt frame's esp
		esp_ = (char *)if_.esp;
		//Make token_ points to the same string as token
		token_ = token;
		//coping the string in token to esp byte by byte
		while(*token_ != '\0'){
			*esp_++ = *token_++;
		}
		//Add the end of string character
		*esp_ = '\0';
		//Add the argument length to full_length
		full_length += strlen(token);
	}
	//Add the allignment bytes
	for(i = 0; i < (full_length % 4); i++){
		if_.esp -= 1;
		*((uint8_t *)if_.esp) = 0;
	}
	//Add null pointer sentinal
	if_.esp -= 4;
    *((char *)if_.esp) = 0;
    //Add the addresses of the arguments
	for(i = num_of_args - 1; i >= 0; i--){
		if_.esp -= 4;
		*((char **)if_.esp) = addrs[i];
	}
	//Add the address of the first address of the arguments
	if_.esp -= 4;
	*((char ***)if_.esp) = (if_.esp + 4);
	//Add the number of arguments
	if_.esp -= 4;
	*((int *)if_.esp) = num_of_args;
	//Add the fake return address
	if_.esp -= 4;
	*((int *)if_.esp) = 0;


  }


  /* child sleeps it self tell parent intialize the sharable semaphore object */
  sema_down (&cur->thread_ready);

  /* If load failed, quit. */
  palloc_free_page (cmdline_);
  if (!success) 
    {
      cur->terminate_status = -1;
      cur->semaphore_object->has_error = -1;
  	  sema_up (&cur->semaphore_object->sema);
      thread_exit ();
    }
  else
    {
      /* Sends message to the parent to informs it with loading*/
    	cur->semaphore_object->has_error = 1;
  	  	sema_up (&cur->semaphore_object->sema);
    }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread_child *child = current_thread_get_child (child_tid);

  if (child == NULL )
    return -1;

  /* Waits for the child to exit and send its exit status. */
  sema_down (&child->semaphore_object.sema);
  int exit_msg = child->semaphore_object.has_error;



  /* Removes child to ensure that the parent waits on
     its child at most once. */
  remove_child (child);

  return exit_msg;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  printf ("%s: exit(%d)\n", cur->name, cur->terminate_status);
  
  /* Releases all the resources of the thread. */
  close_all_files ();
  thread_remove_children ();
  
  if (cur->semaphore_object != NULL){
  	/* Sends a message to the parent contains exit status. */
  	  cur->semaphore_object->has_error = cur->terminate_status;
  	  sema_up (&cur->semaphore_object->sema);
  }
    

  /* Releases locks if acquired. */
  if (lock_held_by_current_thread (&file_lock))
    lock_release (&file_lock);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmdline_, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;					//For the loop
  char *cmdline;			//to copy the cmdline_ to not destroy it
  char *file_name;			//String to save the file name without the arguments to be excuted 
  char *save_ptr;			//For strtok_r

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  cmdline = malloc ((strlen(cmdline_) + 1));		//Save space for cmdline
  if (cmdline == NULL)
      goto done;
  strlcpy (cmdline, cmdline_, PGSIZE);				//Copy cmdline_ to cmdline

  file_name = strtok_r (cmdline, " ", &save_ptr);	//Save the file name to file_name

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  free (cmdline);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
 /* We arrive here whether the load is successful or not. */
  if (success)
   {
     thread_current ()->executable = file;
     /* Denies write to executable files. */
     file_deny_write (file);
   }
  else
    file_close (file);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


//static char *extract_file_name (const char *cmdline)
static char *get_file_name (const char *cmdline)
{
  char *save_ptr;
  char *file_name = malloc ((strlen (cmdline) + 1) * sizeof(char));

  if (file_name == NULL)
      return NULL;

  strlcpy (file_name, cmdline, PGSIZE);
  file_name = strtok_r (file_name, " ", &save_ptr);

  return file_name;
}


static void remove_child (struct thread_child *child)
{
	struct thread *c = thread_get (child->tid);

  /* Destroys the shared mailbox. */
  if (c != NULL)
  	c->semaphore_object = NULL;

  /* Removes child from the parent CHILD_LIST. */
  list_remove (&child->elem);
  /* Destroys the child. */
  free (child);
}

static struct thread_child *current_thread_get_child (pid_t pid)
{
  struct list_elem *e;
  struct thread *parent = thread_current ();

  for (e = list_begin (&parent->child_list); e != list_end (&parent->child_list);
       e = list_next (e))
    {
      struct thread_child *c = list_entry (e, struct thread_child, elem);
      if (c->tid == pid)
        return c;
    }

  return NULL;
}

void
fd_close (struct file_directory_entry *f)
{
  lock_acquire (&file_lock);
  file_close (f->file);
  lock_release (&file_lock);
  list_remove (&f->elem);
  free (f);
}


static void
close_all_files (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->opened_files);
  
  while (e != list_end (&cur->opened_files))
    {
      struct file_directory_entry *f = list_entry (e, struct file_directory_entry, elem);
      e = list_next (e);
      fd_close (f);
    }

  file_close (cur->executable);
}

//this method iterate for all thread's children and removes them by calling remove_child() method
static void
thread_remove_children (void)
{
   struct thread *cur = thread_current ();
   struct list_elem *e = list_begin (&cur->child_list);;

   while (e != list_end (&cur->child_list))
     {
      struct thread_child *child = list_entry (e, struct thread_child, elem);
       e = list_next (e);
       remove_child (child);
     }
}

