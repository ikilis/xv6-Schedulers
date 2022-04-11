#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// ADDED general purpose variables
int number_of_active_proces = 0;            // Number of active process

uint alpha = 50;                            // Used if SJF, part of 100
int scheduler_type = CFS;     // Default shceduler type
struct proc* myScheduler[NPROC];            // Heap used for scheduling
struct spinlock sched_lock;                 // Lock for the scheduler
int scheduler_size = 0;                     // Number of processes in scheduler

uint current_tick = 0;                     // Helping variable

int my_scheduler_type(){return scheduler_type;}
void set_scheduler_type(int type){
    scheduler_type = type;
    create_heap();
}
void set_alpha(int a){alpha = a;}

// ADDED heap functions
void create_heap(){
    acquire(&sched_lock);
    int n = scheduler_size;
    for (int i =0;i<n;i++){
        myScheduler[i]->total_execution_time =  0;

        if(scheduler_type == CFS) myScheduler[i]->predicted_time = 1;
        else myScheduler[i]->predicted_time = 0;

        myScheduler[i]->time_slice = 0;
    }
    release(&sched_lock);
}



struct
proc* heap_peak(){
    acquire(&sched_lock);
    if (scheduler_size > 0){
        release(&sched_lock);
        return myScheduler[0];
    }
    release(&sched_lock);
    return 0;
}

void
heap_swap(int i, int j){
    struct proc* t = myScheduler[i];
    myScheduler[i] = myScheduler[j];
    myScheduler[j] = t;
}

int
heap_left(int i){
    return i*2+1;
}

int
heap_right(int i){
    return i*2+2;
}

int
heap_min(int i, int j){
    if (scheduler_type == SJF_NONPREEMPTIVE || scheduler_type == SJF_NONPREEMPTIVE){
        if(myScheduler[i]->predicted_time > myScheduler[j]->predicted_time) return j;
        return i;
    }
    // If it is CFS scheduler
    if(myScheduler[i]->total_execution_time > myScheduler[j]->total_execution_time) return j;
    return i;
}

// ADDED scheduler operations based on sheduler type
///////////////////////// PUT FUNCTIONS
void
put_CFS(struct proc* p){
    int curr_index = scheduler_size;
    myScheduler[scheduler_size] = p;
    scheduler_size++;
    p->blocked_tick = current_tick;
    int parent = 0;
    while (curr_index != 0){
        parent = ((curr_index%2)?curr_index-1:curr_index-2)/2;
        if (myScheduler[parent]->total_execution_time > myScheduler[curr_index]->total_execution_time){
            heap_swap(parent,curr_index);
        }
        else{
            break;
        }
        curr_index = parent;
    }
}
void
put_SJF(struct proc *p){
    int curr_index = scheduler_size;
    myScheduler[scheduler_size] = p;
    scheduler_size++;

    if(p->was_interupted){

        p->predicted_time = (p->time_slice * alpha + p->predicted_time * (100 - alpha)) / 100;
        p->was_interupted = 0;
    }
    int parent = 0;
    while (curr_index != 0){
        parent = ((curr_index%2)?curr_index-1:curr_index-2)/2;
        if (myScheduler[parent]->predicted_time > myScheduler[curr_index]->predicted_time){
            heap_swap(parent,curr_index);
        }
        else{
            break;
        }
        curr_index = parent;
    }
}
///////////////////////// GET FUNCTIONS
struct proc*
get_CFS(){
    struct proc * ret = myScheduler[0];


    ret->predicted_time = (current_tick-ret->blocked_tick)/number_of_active_proces;
    if (ret->predicted_time < 1){
        ret->predicted_time = 1;
    }
    ret -> time_slice = 0;

    scheduler_size--;
    int curr_index = 0;
    myScheduler[0] = myScheduler[scheduler_size];
    while(curr_index < scheduler_size/2){
        int child = heap_min(heap_left(curr_index),heap_right(curr_index));
        if(myScheduler[child]->total_execution_time > myScheduler[curr_index]->total_execution_time)    break;

        heap_swap(curr_index,child);
        curr_index = child;
    }
    return ret;
}
struct proc*
get_SJF(){
    struct proc *ret = myScheduler[0];
    ret-> time_slice = 0;
    scheduler_size--;
    int curr_index = 0;
    myScheduler[0] = myScheduler[scheduler_size];

    while(curr_index < scheduler_size/2){
        int child = heap_min(heap_left(curr_index), heap_right(curr_index));
        if( myScheduler[child]->predicted_time > myScheduler[curr_index]->predicted_time)   break;

        heap_swap(curr_index, child);
        curr_index = child;
    }
    return ret;
}
//////////////////////// GLOBAL FUNCTIONS
void
put(struct proc *p){
    acquire(&sched_lock);
    if (scheduler_size == NPROC || p->state != RUNNABLE){     // ERRORS
        release(&sched_lock);
        return;
    }
    if(scheduler_type == SJF_NONPREEMPTIVE || scheduler_type == SJF_PREEMPTIVE) put_SJF(p);

    else                                                                                 // IF CFS, then CFS put
        put_CFS(p);

    release(&sched_lock);
}

struct proc*
get(){

    acquire(&sched_lock);
    if(scheduler_size == 0){
        release(&sched_lock);
        return 0;
    }
    struct proc * ret;

    if(scheduler_size == 0) ret = 0;
    if(scheduler_type == CFS)  ret = get_CFS();
    else ret = get_SJF();

    release(&sched_lock);
    return ret;

}
// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl) {
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table at boot time.      // ADDED SCHEDULER LOCK INITIALIZATION
void
procinit(void)
{
  struct proc *p;
  initlock(&sched_lock, "sched_lock");
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->kstack = KSTACK((int) (p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void) {
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc*
myproc(void) {
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int
allocpid() {
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*                                                         //////// CHANGED ADDED STARITON PROC VALUES
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  number_of_active_proces++;
  p->time_slice = 0;
  p->total_execution_time = 0;
  p->blocked_tick = current_tick;
  p->was_interupted = 0;
  if(scheduler_type == CFS) p->predicted_time = 1;
  else p->predicted_time = 0;

  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process,
// with no user memory, but with trampoline pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe just below TRAMPOLINE, for trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// od -t xC initcode
uchar initcode[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
  0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
  0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
  0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
  0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
  0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  // allocate one user page and copy init's instructions
  // and data into it.
  uvminit(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  put(p);

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)          /////////////// CHANGED - new proces inherits atributes of it's parent
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->predicted_time = p->predicted_time;
  np->total_execution_time = p->total_execution_time;
  np->time_slice = p->time_slice;
  np->was_interupted = p->was_interupted;
  np->blocked_tick = current_tick;

  np->state = RUNNABLE;
  number_of_active_proces++;
  put(np);
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
exit(int status)
{


  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);
  
  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&wait_lock);
  number_of_active_proces--;
    // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(uint64 addr)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(np = proc; np < &proc[NPROC]; np++){
      if(np->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&np->lock);

        havekids = 1;
        if(np->state == ZOMBIE){
          // Found one.
          pid = np->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                  sizeof(np->xstate)) < 0) {
            release(&np->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&wait_lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || p->killed){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
    struct proc *p;
    struct cpu *c = mycpu();

    c->proc = 0;
    for(;;){
        // Avoid deadlock by ensuring that devices can interrupt.
        intr_on();
        p = get();
        if (p == 0 || p->state != RUNNABLE){
            continue;
        }
        acquire(&p->lock);

        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);
        c->proc = 0;

        release(&p->lock);
        /*
        for(p = proc; p < &proc[NPROC]; p++) {
          acquire(&p->lock);
          if(p->state == RUNNABLE) {
            // Switch to chosen process.  It is the process's job
            // to release its lock and then reacquire it
            // before jumping back to us.
            p->state = RUNNING;
            c->proc = p;
            swtch(&c->context, &p->context);

            // Process is done running for now.
            // It should have changed its p->state before coming back.
            c->proc = 0;
          }
          release(&p->lock);
        }*/

    }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  put(p);
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void                                        /////// CHANGED - remmember that he was interrupted and decrement num of active processes
sleep(void *chan, struct spinlock *lk)
{

  number_of_active_proces--;
  myproc()->was_interupted = 1;
  struct proc *p = myproc();

  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void
wakeup(void *chan)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      acquire(&p->lock);
      if(p->state == SLEEPING && p->chan == chan) {
        p->state = RUNNABLE;
        number_of_active_proces++;
        put(p);
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        p->state = RUNNABLE;
        put(p);
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}
