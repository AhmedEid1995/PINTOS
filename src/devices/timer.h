#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

/* Sleep and yield the CPU to other threads. */
void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

/* Busy waits. */
void timer_mdelay (int64_t milliseconds);
void timer_udelay (int64_t microseconds);
void timer_ndelay (int64_t nanoseconds);

void timer_print_stats (void);



/*
  Struct for representing a thread that is sleeping
  Struct consist of :
    sleeping_thread_semaphore : which block and unblock the thread while inserting it into sleeping list
    time_to_wake_up : time to describe when the thread should be waked up
    element_list : list used to traverse throw the list of sleeping threads and it is used to complete interface of functions

*/
struct sleeping_thread{
    /* this semaphore is used to block and unblock sleeping thread*/
    struct semaphore sleeping_thread_semaphore;
    /* time when thread should waked up*/
    int64_t time_to_wake_up;
    /* List element used to traverse throw the list of sleeping threads
      and complete required parameters */
    struct list_elem auxiliary_list;
};



#endif /* devices/timer.h */
