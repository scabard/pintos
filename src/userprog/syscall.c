#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
/* for shutdown_power_off */
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

struct lock fs_lock;
struct list open_files;
struct file_desc
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

static void syscall_handler (struct intr_frame *);

/* System call functions */
static void halt (void);
static void exit (int);
static pid_t exec (const char *);
static int wait (pid_t);
static bool create (const char*, unsigned);
static bool remove (const char *);
static int open (const char *);
static int filesize (int);
static int read (int, void *, unsigned);
static int write (int, const void *, unsigned);
static void seek (int, unsigned);
static unsigned tell (int);
static void close (int);

static struct file_desc *get_open_file (int);
static void close_open_file (int);
bool is_valid_ptr (const void *);
static int allocate_fd (void);
void close_file_by_owner (tid_t);



void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
  list_init(&open_files);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t *esp;
  esp = f->esp;

  if (!is_valid_ptr (esp) || !is_valid_ptr (esp + 1) ||
      !is_valid_ptr (esp + 2) || !is_valid_ptr (esp + 3))
    // exit (-1);
    {}
  else
  {
    switch(*esp)
    {
      // case SYS_HALT:
      //   halt ();
      //   break;
      // case SYS_EXIT:
      //   exit (*(esp + 1));
      //   break;
      case SYS_EXEC:
        f->eax = exec ((char *) *(esp + 1));
        break;
      // case SYS_WAIT:
      //   f->eax = wait (*(esp + 1));
      //   break;
      case SYS_CREATE:
        f->eax = create ((char *) *(esp + 1), *(esp + 2));
        break;
      case SYS_REMOVE:
        f->eax = remove ((char *) *(esp + 1));
        break;
      case SYS_OPEN:
        f->eax = open ((char *) *(esp + 1));
        break;
      // case SYS_FILESIZE:
      //   f->eax = filesize (*(esp + 1));
      //   break;
      case SYS_READ:
        f->eax = read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
      // case SYS_WRITE:
      //   f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      //   break;
      // case SYS_SEEK:
      //   seek (*(esp + 1), *(esp + 2));
      //   break;
      // case SYS_TELL:
      //   f->eax = tell (*(esp + 1));
      //   break;
      // case SYS_CLOSE:
      //   close (*(esp + 1));
      //   break;
      default:
        break;
    }
  }
  // printf ("system call!\n");
  // thread_exit ();
}

bool
create (const char *file_name, unsigned size)
{
  bool status;

  if(!is_valid_ptr(file_name))
    {}

  lock_acquire(&fs_lock);
  status = filesys_create(file_name, size);
  lock_release(&fs_lock);
  return status;
}

bool
remove (const char *file_name)
{
  bool status;
  if (!is_valid_ptr (file_name))
  {}
    // exit (-1);

  lock_acquire (&fs_lock);
  status = filesys_remove (file_name);
  lock_release (&fs_lock);
  return status;
}

pid_t
exec (const char *cmd_line)
{
  tid_t tid;
  struct thread *cur;
  /* check if the user pinter is valid */
  if (!is_valid_ptr (cmd_line))
    {
      // exit (-1);
    }

  cur = thread_current ();

  cur->child_status = 0;
  tid = process_execute (cmd_line);
  lock_acquire(&cur->c_lock);
  while (cur->child_status == 0)
    cond_wait(&cur->c_cond, &cur->c_lock);
  if (cur->child_status == -1)
    tid = -1;
  lock_release(&cur->c_lock);
  return tid;
}

int
open (const char *file_name)
{
  struct file *f;
  struct file_desc *fd;
  int status = -1;

  if(!is_valid_ptr(file_name)) {

  }
    // exit(-1);

  lock_acquire(&fs_lock);
  f = filesys_open(file_name);
  if(f != NULL)
  {
    fd = calloc(1, sizeof(*fd));
    fd->fd_num = allocate_fd();
    fd->owner = thread_current();
    fd->file_struct = f;
    list_push_back(&open_files, &fd->elem);
    status = fd->fd_num;
  }
  lock_release(&fs_lock);
  return status;
}

int
read (int fd, void *buffer, unsigned size)
{
    struct file_desc *fd_struct;
  int status = 0;

  if (!is_valid_ptr (buffer) || !is_valid_ptr (buffer + size - 1))
  {}
    // exit (-1);

  lock_acquire (&fs_lock);

  if (fd == STDOUT_FILENO)
    {
      lock_release (&fs_lock);
      return -1;
    }

  if (fd == STDIN_FILENO)
    {
      uint8_t c;
      unsigned counter = size;
      uint8_t *buf = buffer;
      while (counter > 1 && (c = input_getc()) != 0)
        {
          *buf = c;
          buffer++;
          counter--;
        }
      *buf = 0;
      lock_release (&fs_lock);
      return (size - counter);
    }

  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_read (fd_struct->file_struct, buffer, size);

  lock_release (&fs_lock);
  return status;
}

struct file_desc *
get_open_file (int fd)
{
  struct list_elem *e;
  struct file_desc *fd_struct;
  e = list_tail (&open_files);
  while ((e = list_prev (e)) != list_head (&open_files))
    {
      fd_struct = list_entry (e, struct file_desc, elem);
      if (fd_struct->fd_num == fd)
	return fd_struct;
    }
  return NULL;
}

bool
is_valid_ptr(const void *ptr)
{
  struct thread *curr = thread_current();
  if(ptr != NULL && is_user_vaddr(ptr))
  {
    return (pagedir_get_page(curr->pagedir, ptr)) != NULL;
  }
  return false;
}

int
allocate_fd(void)
{
  // unique file descriptor for every thread which opens the same file
  static int fd = 1;
  return ++fd;
}

void
close_file_by_owner (tid_t tid)
{
  struct list_elem *e;
  struct list_elem *next;
  struct file_desc *fd_struct;
  e = list_begin (&open_files);
  while (e != list_tail (&open_files))
    {
      next = list_next (e);
      fd_struct = list_entry (e, struct file_desc, elem);
      if (fd_struct->owner == tid)
	{
	  list_remove (e);
	  file_close (fd_struct->file_struct);
          free (fd_struct);
	}
      e = next;
    }
}