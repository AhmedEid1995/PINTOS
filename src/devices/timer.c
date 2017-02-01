#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "devices/pit.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom );
static void real_time_delay (int64_t num, int32_t denom);
/*
  This function is used to ocmpare between two thread which will wake up before the other
  Parameters : two sleeping threads
  Return : return true or flase which indicate which one has smaller sleeping time
*/
static bool sleeping_threads_comparable (struct list_elem *x, struct list_elem *y,void *aux UNUSED);
/* List of sleeping threads used built in list implementation from list.c
   to store all sleeping threads in program
*/
struct list sleeping_threads_list;

/* Sets up the timer to interrupt TIMER_FREQ times per second,
   and registers the corresponding interrupt. */
void
timer_init (void)
{
  pit_configure_channel (0, 2, TIMER_FREQ);
  intr_register_ext (0x20, timer_interrupt, "8254 Timer");
  /*
    intialize sleeping threads list
  */
  list_init (&sleeping_threads_list);
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
  timer_calibrate (void)
{
  unsigned high_bit, test_bit;

  ASSERT (intr_get_level () == INTR_ON);
  printf ("Calibrating timer...  ");

  /* Approximate loops_per_tick as the largest power-of-two
     still less than one timer tick. */
  loops_per_tick = 1u << 10;
  while (!too_many_loops (loops_per_tick << 1))
    {
      loops_per_tick <<= 1;
      ASSERT (loops_per_tick != 0);
    }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops (high_bit | test_bit))
      loops_per_tick |= test_bit;

  printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void)
{
  enum intr_level old_level = intr_disable ();
  int64_t t = ticks;
  intr_set_level (old_level);
  return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then)
{
  return timer_ticks () - then;
}
/************************************************************************************************************************/
/*
  We Edit in this function to convert sleeping mode from busy waiting to
  block threaad and store it in sleeping thread list unitl its time to block end
  then we unblock it.

*/
void timer_sleep (int64_t ticks) {

  int64_t start = timer_ticks ();
  ASSERT (intr_get_level () == INTR_ON);
  // create sleeeping thread to add it into sleeping thread list
  struct sleeping_thread current_sleeping_thread;
  sema_init (&current_sleeping_thread.sleeping_thread_semaphore, 0);    //intialize semaphore with 0 value
  // calcualte required time to know when we should wake up the sleeping thread
  current_sleeping_thread.time_to_wake_up = start + ticks ;
  // disable the interrupts
  enum intr_level level_of_Interrupt = intr_disable ();
  // Insert sleeping threaad into sleeping threads list in order of walking up time used sleeping_threads_comparable method
  list_insert_ordered (&sleeping_threads_list, &current_sleeping_thread.auxiliary_list, &sleeping_threads_comparable, NULL);
  //block this thread as sleeping thread after inserting it into sleeping threads list
  sema_down (&current_sleeping_thread.sleeping_thread_semaphore);
  // enable the interrupts
  intr_set_level (level_of_Interrupt);
}

/*
  This function is used to ocmpare between two thread which will wake up before the other
  Parameters : two sleeping threads
  Return : return true or flase which indicate which one has smaller sleeping time
*/
bool sleeping_threads_comparable (struct list_elem *x, struct list_elem *y,void *aux UNUSED){
  // get two sleeping thread to compare and get smaller one
  struct sleeping_thread * x_sleeping = list_entry (x, struct sleeping_thread, auxiliary_list);
  struct sleeping_thread * y_sleeping = list_entry (y, struct sleeping_thread, auxiliary_list);
  return (x_sleeping->time_to_wake_up <= y_sleeping->time_to_wake_up);
}

/**********************************************************************************************************************/
/* Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void
timer_msleep (int64_t ms)
{
  real_time_sleep (ms, 1000);
}

/* Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void
timer_usleep (int64_t us)
{
  real_time_sleep (us, 1000 * 1000);
}

/* Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void
timer_nsleep (int64_t ns)
{
  real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Busy-waits for approximately MS milliseconds.  Interrupts need
   not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_msleep()
   instead if interrupts are enabled. */
void
timer_mdelay (int64_t ms)
{
  real_time_delay (ms, 1000);
}

/* Sleeps for approximately US microseconds.  Interrupts need not
   be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_usleep()
   instead if interrupts are enabled. */
void
timer_udelay (int64_t us)
{
  real_time_delay (us, 1000 * 1000);
}

/* Sleeps execution for approximately NS nanoseconds.  Interrupts
   need not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_nsleep()
   instead if interrupts are enabled.*/
void
timer_ndelay (int64_t ns)
{
  real_time_delay (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void)
{
  printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}


/*********************************************************************************************************************/
/* Timer interrupt handler. */
static void timer_interrupt (struct intr_frame *args UNUSED) {
  ticks++;
  //disble interrupt
  enum intr_level level_of_Interrupt = intr_disable ();

  struct list_elem * current_auxiliary_list;
  struct sleeping_thread * current_sleeping_thread;

if (thread_mlfqs)
    {
      thread_increment_recent_cpu ();
      if (ticks % TIMER_FREQ == 0){
       threads_update_recent_cpu();
       
      }
      if (ticks % 4 == 0)
       threads_update_priority();
    }

  /*
    iterate throw all the sleeping threads to update its state
  */
  while ( !list_empty (&sleeping_threads_list)){
      current_auxiliary_list = list_pop_front (&sleeping_threads_list);
      current_sleeping_thread = list_entry (current_auxiliary_list, struct sleeping_thread, auxiliary_list);
      // check if thread should be waked up or still sleeping
      if (current_sleeping_thread -> time_to_wake_up <= ticks){
          //wake up sleeping thread
          sema_up (&current_sleeping_thread->sleeping_thread_semaphore);
      }else{
          /*
            Still sleeping and we insert threaads in order so we dont need to chceck other threads
            Because we are sure that all still sleeping also
          */
         list_push_front (&sleeping_threads_list, current_auxiliary_list);
         break;
      }
  }
  thread_tick ();
  //enable interrupt
  intr_set_level (level_of_Interrupt);
}
/**************************************************************************************************************************/
/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops)
{
  /* Wait for a timer tick. */
  int64_t start = ticks;
  while (ticks == start)
    barrier ();

  /* Run LOOPS loops. */
  start = ticks;
  busy_wait (loops);

  /* If the tick count changed, we iterated too long. */
  barrier ();
  return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops)
{
  while (loops-- > 0)
    barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom)
{
  /* Convert NUM/DENOM seconds into timer ticks, rounding down.

        (NUM / DENOM) s
     ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
     1 s / TIMER_FREQ ticks
  */
  int64_t ticks = num * TIMER_FREQ / denom;

  ASSERT (intr_get_level () == INTR_ON);
  if (ticks > 0)
    {
      /* We're waiting for at least one full timer tick.  Use
         timer_sleep() because it will yield the CPU to other
         processes. */
      timer_sleep (ticks);
    }
  else
    {
      /* Otherwise, use a busy-wait loop for more accurate
         sub-tick timing. */
      real_time_delay (num, denom);
    }
}

/* Busy-wait for approximately NUM/DENOM seconds. */
static void
real_time_delay (int64_t num, int32_t denom)
{
  /* Scale the numerator and denominator down by 1000 to avoid
     the possibility of overflow. */
  ASSERT (denom % 1000 == 0);
  busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
}
