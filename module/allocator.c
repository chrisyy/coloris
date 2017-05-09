/*
 *  Copyright (C) 2013-2014  Ying Ye, PhD Candidate, Boston University
 *  Advisor: Richard West
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tty.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm-generic/memory_model.h>
#include <asm/tlbflush.h>
#include <asm/msr.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/color_alloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/rwsem.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/cpumask.h>
#include <linux/ioctl.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include "list.h"

/* XXX: Multi-threading not supported yet */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ying Ye <yingy@bu.edu>");

//#define ALLOC_DEBUG
#define REDISTRIBUTION
//#define SEL_MOVE
#define REC_COUNT
#define TEST_TIME 3600


#define MY_CHECK_ALL      _IOW(0, 0, long)
#define MY_CHECK_ONE      _IOW(0, 1, long)
#define MY_CHECK_RESERVE  _IOW(0, 2, long)
#define MY_CHECK_FILE     _IOW(0, 3, long)
#define MY_CHECK_IPC      _IOW(0, 4, long)
#define MY_CHECK_HOT      _IOW(0, 5, long)

static struct file_operations proc_operations;
static struct proc_dir_entry *proc_entry;
int debug_ioctl(struct file *, unsigned int, unsigned long);


extern struct page * (*colored_alloc)(struct mm_struct *mm, int zero);
extern struct page * (*colored_alloc_file)(struct file *filp);
extern void (*assign_colors)(struct mm_struct *mm);
extern int (*colored_free)(struct page *pg, struct zone *zone);
extern int (*check_apps)(struct file *filp);
extern int (*recolor_mm)(struct mm_struct *mm, int isExpand);
extern void (*color_collect)(struct mm_struct *mm);
extern void (*finish_recolor)(struct mm_struct *mm);
extern void (*collect_inst)(struct task_struct *task);
extern int cmr_high_threshold;
extern int cmr_low_threshold;
extern int recolor_delay;
extern unsigned int sample_stages[NR_CPUS];

/* 
 * 32-bit system, LLC size 4MB, 16 ways, page size 4KB
 * color number = (LLC size / number of ways) / page size
 */
#define PG_SIZE (4*1024)
#define WAY_ASSOC 16
/* if color number is changed, GET_COLOR should be modified */
#define COLOR_NUM 64
/* 1GB RAM for coloring */
#define RAM_SIZE (1024*1024*1024)
/* 4 cores */
#define NUM_CORES 4

/* number of applications supported */
#define MAX_APPS 30

/* recoloring parameters */
#define CMR_HIGH_INIT 75
#define CMR_LOW_INIT 30
#define SAMPLE_PERIOD 5
#define REC_DELAY 10
#define MAX_COLORS 48
#define MIN_COLORS 4
#define SCAN_WIN 3000000
#define COLORS_ONCE 4
#define COLORS_TRY 4

struct _Scanner {
  struct hrtimer timer;
  int working;
  spinlock_t lock;
};

static struct _Scanner scanner;

/* array of colors */
static LIST color_lists[COLOR_NUM];
/* 
 * used when filling in memory pool
 * page of unwanted color should not be freed before pool is full
 * otherwise, it may be reallocated to us again and again
 */
static LIST page_buf;
/* locks for each color list */
static spinlock_t color_locks[COLOR_NUM];

/* 
 * hotness for every color 
 * count: global hotness
 * remote: remote hotness
 */
struct _GHotness {
  spinlock_t lock;
  int count[COLOR_NUM];
  int remote[COLOR_NUM];
};

static struct _GHotness global_hotness;


static int pg_num;
static struct page template;
static int e_counter = 0;

static char *apps[MAX_APPS];
static int nr_apps;
module_param_array(apps, charp, &nr_apps, 0644);

static int qos_pair[2*MAX_APPS];
module_param_array(qos_pair, int, NULL, 0644);

struct MyQoS {
  int high[MAX_APPS];
  int low[MAX_APPS];
};

static struct MyQoS app_qos;

static int quanta[MAX_APPS];

static struct color_set assignment[MAX_APPS];
static unsigned int cpu_pin[MAX_APPS];

static unsigned int app_inst_l[MAX_APPS];
static unsigned int app_inst_h[MAX_APPS];
static unsigned int app_ref_l[MAX_APPS];
static unsigned int app_ref_h[MAX_APPS];
static unsigned int app_miss_l[MAX_APPS];
static unsigned int app_miss_h[MAX_APPS];

static spinlock_t app_locks[MAX_APPS];

/* XXX: only needed for coloring code segment */
struct pureHack {
  int hit[MAX_APPS];
  struct address_space *mapping[MAX_APPS];
  struct address_space *target[MAX_APPS];
  int cur_color[MAX_APPS];
};

static struct pureHack hackdata;

static const unsigned int select_msr_inst = 0xC0 | (0x00 << 8) | (0x01 << 16) 
                                          | (0x01 << 22);
static const unsigned int select_msr_cyc = 0x3C | (0x00 << 8) | (0x01 << 16) 
                                          | (0x01 << 22);
static const unsigned int select_msr_ref = 0x2E | (0x4F << 8) | (0x01 << 16) 
                                          | (0x01 << 22);
static const unsigned int select_msr_miss = 0x2E | (0x41 << 8) | (0x01 << 16)
					  | (0x01 << 22);
static struct hrtimer ipc_timer[NUM_CORES];
static int ipc_sig[NUM_CORES];
static struct hrtimer sample_timer[NUM_CORES];
static spinlock_t ipc_lock;
static volatile int ipc_apps = 0;

/* *********Utilities********* */
#define GET_COLOR(pfn) (pfn & 0x3F)


static void init_check(void) {

  int i, j;
  for (i = 0; i < COLOR_NUM; i++) {
    if (color_lists[i].num != pg_num) {
      printk(KERN_ERR "color %d not full: %d pages\n", i, color_lists[i].num);
    }

    struct list_head *cur = color_lists[i].head;
    int flag = 0;
    for (j = 0; j < pg_num; j++) {
      if (GET_COLOR(page_to_pfn(list_to_page(cur))) != i) {
        flag = 1;
      }
      cur = cur->next; 
    }

    if (flag) {
      printk(KERN_ERR "color %d has pages of different colors\n", i);
    }
  }
}

static inline void check_page(struct page *pg);

static void free_list_pgs(LIST *list) {

  struct page *pg;
  while(list->num > 0) {
    pg = list_remove(list);

#ifdef ALLOC_DEBUG
    check_page(pg);
#endif

    pg->lru.next = LIST_POISON1;
    pg->lru.prev = LIST_POISON2;
    __free_page(pg);
  }
}

static void check_lists(void) {

  int i, flag = 0;
  for (i = 0; i < COLOR_NUM; i++) {
    if (color_lists[i].num != 0) {
      flag = 1;
      printk(KERN_ERR "color not freed: %d\n", i);
      free_list_pgs(&color_lists[i]);
    }
  }
  if (flag) printk(KERN_ERR "Memory pool not freed completely!\n");
}

static inline void my_dump_page(struct page *pg) {

  printk(KERN_ERR "page %x: %x %x %x %x %x %x %x %x\n", (unsigned long)pg, pg->flags, 
        pg->_count.counter, pg->_mapcount.counter, pg->private, (long)pg->mapping, 
        pg->index, (unsigned long)pg->lru.next, (unsigned long)pg->lru.prev);
}

static inline void check_page(struct page *pg) {

  if (pg->_count.counter != template._count.counter) goto next;
  if (pg->_mapcount.counter != template._mapcount.counter) goto next;
  if (pg->mapping != template.mapping) goto next;
  if (pg->lru.next != template.lru.next) goto next;
  if (pg->lru.prev != template.lru.prev) goto next;
  if ((pg->flags & ((1 << __NR_PAGEFLAGS) - 1)) != 
    (template.flags & ((1 << __NR_PAGEFLAGS) - 1))) goto next;

  return;

next:
  e_counter++;
  my_dump_page(pg);
}

static inline void zero_page(struct page *pg) {

  void *addr = kmap_atomic(pg);

  memset(addr, 0, PG_SIZE);
  kunmap_atomic(addr);
}

static void check_assignment(int index) {

  int j;
  
  printk(KERN_ERR "%s:", apps[index]);
  for (j = 0; j < quanta[index]; j++) {
    printk(KERN_ERR " %d", assignment[index].colors[j]);
  }
  printk(KERN_ERR "\n");
}

/* str1 should be the string to be checked */
static int string_eq(char *str1, char *str2) {

  int i = 0;
  while(str1[i] != '\0' && str2[i] != '\0') {
    if (str1[i] != str2[i]) return 0;
    i++;
  }

  if (str2[i] != '\0') return 0;
  else return 1;
}


struct page *alloc_colored_page(struct mm_struct *mm, int zero);
void get_color_set(struct mm_struct *mm);
int free_colored_page(struct page *pg, struct zone *zone);
int apps_check(struct file *filp);
struct page *alloc_colored_page_file(struct file *filp);
int mm_recoloring(struct mm_struct *mm, int isExpand);
void GHot_update(struct mm_struct *mm, int total);
void release_colors(struct mm_struct *mm);
void move_pages(struct mm_struct *mm);
void inst_read(struct task_struct *task);
int fire_timer(void *arg);

/* *********Allocator********* */

static int __init alloc_init(void) {

  proc_operations.unlocked_ioctl = debug_ioctl;

  proc_entry = create_proc_entry("alloc", 0444, NULL);
  if (!proc_entry) {
    printk(KERN_ERR "Error creating /proc entry.\n");
    return 1;
  }

  proc_entry->proc_fops = &proc_operations;

  pg_num = RAM_SIZE / (COLOR_NUM * PG_SIZE);
  struct page *new_pg;
  int k;

  if (PG_SIZE != PAGE_SIZE) {
    printk(KERN_ERR "only 4KB page size is supported!\n");
    return 1;
  }

  cmr_high_threshold = CMR_HIGH_INIT;
  cmr_low_threshold = CMR_LOW_INIT;
  recolor_delay = REC_DELAY;
  for (k = 0; k < NUM_CORES; k++)
    sample_stages[k] = 0;

  spin_lock_init(&scanner.lock);
  scanner.working = 0;

  spin_lock_init(&ipc_lock);

  /* initialize global hotness */
  for (k = 0; k < COLOR_NUM; k++) {
    global_hotness.count[k] = 0;
    global_hotness.remote[k] = 0;
  }
  spin_lock_init(&global_hotness.lock);

  /* initialize locks */
  for (k = 0; k < COLOR_NUM; k++)
    spin_lock_init(&color_locks[k]);

  int start = 0, iter;
  for (iter = 0; iter < nr_apps; iter++)
    quanta[iter] = COLOR_NUM / NUM_CORES;

  for (iter = 0; iter < nr_apps; iter++) {
    if (quanta[iter] > COLOR_BASE) {
      printk(KERN_ERR "quanta is larger than max!\n");
      return 1;
    }

    app_qos.high[iter] = qos_pair[2*iter];
    app_qos.low[iter] = qos_pair[2*iter + 1];

    spin_lock_init(&app_locks[iter]);

    app_inst_h[iter] = 0;
    app_inst_l[iter] = 0;
    app_ref_h[iter] = 0;
    app_ref_l[iter] = 0;
    app_miss_l[iter] = 0;
    app_miss_h[iter] = 0;

    hackdata.cur_color[iter] = 0;

    k = 0;
    while(k < quanta[iter]) {
      assignment[iter].colors[k] = start; 
      k++;
      start = (start + 1) % COLOR_NUM;
    }

    cpu_pin[iter] = assignment[iter].colors[0] / (COLOR_NUM / NUM_CORES);

#ifdef ALLOC_DEBUG
    printk(KERN_ERR "assigned cpu: %d\n", cpu_pin[iter]);
    check_assignment(iter);
#endif

    hackdata.hit[iter] = 0;
  }

  /* fill in memory pool */
  int count = 0, color, num;
  unsigned long frame;

  for (k = 0; k < COLOR_NUM; k++) {
    color_lists[k].num = 0;
    color_lists[k].head = NULL;
  }

  page_buf.num = 0;
  page_buf.head = NULL;

#ifdef ALLOC_DEBUG
  struct page *t_pg;
  t_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE);

  template._count.counter = t_pg->_count.counter;
  template._mapcount.counter = t_pg->_mapcount.counter;
  template.mapping = t_pg->mapping;
  template.lru.next = t_pg->lru.next;
  template.lru.prev = t_pg->lru.prev;
  template.flags = t_pg->flags;
#endif

  while(count != COLOR_NUM) {
    new_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE); 

    frame = page_to_pfn(new_pg);
    color = GET_COLOR(frame);

    num = color_lists[color].num;
    if (num >= pg_num) { /* color list is full */
      list_insert(&page_buf, new_pg);
    }
    else {
#ifdef ALLOC_DEBUG
      check_page(new_pg);
#endif
      if (page_zone(new_pg)->name[0] != 'H') {
        printk(KERN_ERR "pages have to be taken from HighMem\n");
        return 1;
      }

      list_insert(&color_lists[color], new_pg);

      if (color_lists[color].num == pg_num) count++;
    }
  }

#ifdef ALLOC_DEBUG
  __free_page(t_pg);
  printk(KERN_ERR "counter: %d\n", e_counter);
#endif

  /* free page buffer */
  free_list_pgs(&page_buf);

  /* load functions */
  colored_free = free_colored_page;
  color_collect = release_colors;
  colored_alloc = alloc_colored_page;
  colored_alloc_file = alloc_colored_page_file;
  check_apps = apps_check;
  finish_recolor = move_pages;
  collect_inst = inst_read;
  recolor_mm = mm_recoloring;
  assign_colors = get_color_set;

  for (k = 0; k < NUM_CORES; k++)
    kthread_run(fire_timer, (void *)k, "my thread");
  
#ifdef ALLOC_DEBUG
  init_check();
#endif

  printk(KERN_ERR "Allocator loaded!\n");
  return 0;
}


static void __exit alloc_cleanup(void) {

  remove_proc_entry("alloc", NULL);

  int i;
  for (i = 0; i < COLOR_NUM; i++) {
    spin_lock(&color_locks[i]);
  }

  /* unload functions */
  // XXX: synchronization may be needed
  assign_colors = NULL;
  recolor_mm = NULL;
  collect_inst = NULL;
  finish_recolor = NULL;
  check_apps = NULL;
  colored_alloc_file = NULL;
  colored_alloc = NULL;
  color_collect = NULL;
  colored_free = NULL;

  /* free memory pool */
  for (i = 0; i < COLOR_NUM; i++) {
    free_list_pgs(&color_lists[i]);
  }

  for (i = 0; i < COLOR_NUM; i++) {
    spin_unlock(&color_locks[i]);
  }

  /* FIXME: wait for apps to exit module functions */
  schedule();

  for (i = 0; i < COLOR_NUM; i++) {
    spin_lock(&color_locks[i]);
  }

  /* for pages freed after function unloaded */
  for (i = 0; i < COLOR_NUM; i++) {
    free_list_pgs(&color_lists[i]);
  }

  for (i = 0; i < COLOR_NUM; i++) {
    spin_unlock(&color_locks[i]);
  }

  free_list_pgs(&page_buf);

#ifdef ALLOC_DEBUG
  check_lists();
#endif

  printk(KERN_ERR "Allocator unloaded!\n");
}

static struct page *internal_alloc_page(int color) {

  unsigned long flags;

#ifdef ALLOC_DEBUG
  if (color >= COLOR_NUM || color < 0) {
    printk(KERN_ERR "%s: Invalid color!\n", __func__);
    return NULL;
  }
#endif

  spin_lock_irqsave(&color_locks[color], flags);

  /* running out of memory */
  if (color_lists[color].num <= 0) {
    spin_unlock_irqrestore(&color_locks[color], flags);
    return NULL;
  }

  struct page *new_pg = list_remove(&color_lists[color]);

  spin_unlock_irqrestore(&color_locks[color], flags);

#ifdef ALLOC_DEBUG 
  if (new_pg == NULL) {
    printk(KERN_ERR "%s: bug for alloc!\n", __func__);
  }
#endif

  return new_pg;
}

/* called by free_hot_cold_page */
int free_colored_page(struct page *pg, struct zone *zone) {

  unsigned long frame, flags;
  int color;

  /* only take HighMem movable pages */
  if (zone->name[0] != 'H')
    return 0;
  if (pg->index != MIGRATE_MOVABLE)
    return 0;

  frame = page_to_pfn(pg);
  color = GET_COLOR(frame);

  spin_lock_irqsave(&color_locks[color], flags);

  if (color_lists[color].num >= pg_num) {
    spin_unlock_irqrestore(&color_locks[color], flags);
    return 0;
  }
  else {
    atomic_set(&(pg->_count), 1);
    pg->lru.next = LIST_POISON1;
    pg->lru.prev = LIST_POISON2;
    pg->private = 0;

    list_insert(&color_lists[color], pg);

    spin_unlock_irqrestore(&color_locks[color], flags);

    return 1;
  }
}

static int expand_colors(struct mm_struct *mm, int count);

/* called by page fault handler */
struct page *alloc_colored_page(struct mm_struct *mm, int zero) {

  struct page *new_pg;
  int counter = 0;
  struct color_set *set_ptr;

  if (mm == NULL) return NULL;

  if (mm->color_num == 0) return NULL;

  set_ptr = &(mm->my_colors);
RETRY:	
  //spin_lock(&mm->cur_lock);

  do {
    new_pg = internal_alloc_page(set_ptr->colors[mm->color_cur]);
    mm->color_cur = (mm->color_cur + 1) % (mm->color_num);
    counter++;
    /* if color is out of memory, try another one */
  } while(new_pg == NULL && counter < mm->color_num);

  //spin_unlock(&mm->cur_lock);

  if (!new_pg) {
    if (expand_colors(mm, COLORS_ONCE) == 1) {
#ifdef ALLOC_DEBUG
      printk(KERN_ERR "%s: out of memory\n", __func__);
#endif
      return NULL;
    }
    goto RETRY;
  }

  if (zero) zero_page(new_pg);
  return new_pg; 
}

/* ALLOC_COLORS */
static void alloc_colors_file(int index) {

  int num, color, i, j;
  unsigned long flags;

  num = 0;
  //spin_lock(&app_locks[index]);

  do {
    /* first available color not in file */
    for (i = 0; i < COLOR_NUM; i++) {
      for (j = 0; j < quanta[index]; j++)
        if (i == assignment[index].colors[j]) break;

      if ((j == quanta[index]) && (color_lists[i].num > 0)) break;
    }

    int min;

    spin_lock_irqsave(&global_hotness.lock, flags);

    if (quanta[index] >= (COLOR_NUM / NUM_CORES)) {
      /* remote color */
      min = global_hotness.count[i];
      color = i;
      for (i = i + 1; i < COLOR_NUM; i++) {
        if ((global_hotness.count[i] < min) && (color_lists[i].num > 0)) {

          for (j = 0; j < quanta[index]; j++)
            if (i == assignment[index].colors[j]) break;

          if (j == quanta[index]) {
            min = global_hotness.count[i];
            color = i;
          }
        }
      }

      assignment[index].colors[quanta[index]] = color;
      global_hotness.count[color]++;
      global_hotness.remote[color]++;
    }
    else{
      min = INT_MAX;
      color = -1;
      for ( ; i < COLOR_NUM; i++) {
        if ((cpu_pin[index] == i / (COLOR_NUM / NUM_CORES)) && 
          (global_hotness.remote[i] < min) && 
          (color_lists[i].num > 0)) {

          for (j = 0; j < quanta[index]; j++)
            if (i == assignment[index].colors[j]) break;

          if (j == quanta[index]) {
            min = global_hotness.remote[i];
            color = i;
          }
        }
      }

      if (color == -1) {
        printk(KERN_ERR "cpu %d: local memory shortage\n", cpu_pin[index]);
        BUG();
      }

      assignment[index].colors[quanta[index]] = color;
      global_hotness.count[color]++;
    }

    spin_unlock_irqrestore(&global_hotness.lock, flags);
    
    quanta[index]++;
    num++;
  } while(num < COLORS_ONCE);

  //spin_unlock(&app_locks[index]);
}

/* called by __do_page_cache_readahead */
struct page *alloc_colored_page_file(struct file *filp) {

  int i;
  for (i = 0; i < nr_apps; i++) {
    if (string_eq(filp->f_dentry->d_iname, apps[i])) break;
  }

  struct page *pg;
  int index, count;
RETRY:
  //spin_lock(&app_locks[i]);

  index = hackdata.cur_color[i];
  count = 0;
  do {
    pg = internal_alloc_page(assignment[i].colors[index]);
    index = (index + 1) % quanta[i];
    count++;
  } while(pg == NULL && count < quanta[i]);

  hackdata.cur_color[i] = index;

  //spin_unlock(&app_locks[i]);

  if (!pg) {
    /* in target process context */
    if (string_eq(current->comm, apps[i])) {
      if (expand_colors(current->mm, COLORS_ONCE) == 1) {
#ifdef ALLOC_DEBUG
        printk(KERN_ERR "%s: out of memory!\n", __func__);
#endif
        return NULL;
      }
      goto RETRY;
    }
    else {
      if (quanta[i] + COLORS_ONCE > MAX_COLORS) {
#ifdef ALLOC_DEBUG
        printk(KERN_ERR "%s: out of memory!\n", __func__);
#endif
        return NULL;
      }

      alloc_colors_file(i);
      goto RETRY;
    }
  }

  return pg;
}

/* called by generic_perform_write, which calls ext4_da_write_begin */
int apps_check(struct file *filp) {

  int i;
  for (i = 0; i < nr_apps; i++) {
    if (string_eq(filp->f_dentry->d_iname, apps[i])) {
      if (filp->f_mapping == hackdata.target[i] && hackdata.hit[i] == 2) {
        return 1;
      }
      else {
        if (hackdata.hit[i] == 0) {
          hackdata.mapping[i] = filp->f_mapping;
          hackdata.hit[i]++;
          return 0;
        }

        if (hackdata.hit[i] == 1 && hackdata.mapping[i] != filp->f_mapping) {
          hackdata.target[i] = filp->f_mapping;
          hackdata.hit[i]++;
          return 1;
        }

        return 0;
      }
    }
  }

  return 0;
}

/* called by do_execve */
void get_color_set(struct mm_struct *mm) {

#ifdef ALLOC_DEBUG
  if (mm == NULL) {
    printk(KERN_ERR "Invalid mm argument!\n");
    return;
  }
#endif

  int i;
  for (i = 0; i < nr_apps; i++) {
    if (string_eq(current->comm, apps[i])) break;
  }

  /* not a target */
  if (i == nr_apps) {
#ifdef ALLOC_DEBUG
    if (mm->color_num != 0) {
      printk(KERN_ERR "%s: bug!!!!!!!!!!!\n", __func__);
    }
#endif
    mm->color_num = 0;
    return;
  }

  int index = 0;
  struct color_set *set_ptr = &(mm->my_colors);
  unsigned long flags;
 
  spin_lock_irqsave(&global_hotness.lock, flags);
  while(index < quanta[i]) {
    set_ptr->colors[index] = assignment[i].colors[index];
    global_hotness.count[set_ptr->colors[index]]++;
    /* remote color */
    if (cpu_pin[i] != set_ptr->colors[index] / (COLOR_NUM / NUM_CORES))
      global_hotness.remote[set_ptr->colors[index]]++;
    index++;
  }
  spin_unlock_irqrestore(&global_hotness.lock, flags);

  spin_lock(&ipc_lock);
  ipc_apps++;
  spin_unlock(&ipc_lock);

  /* migrate process to the core that owns the colors */
  struct cpumask mask;

  cpumask_clear(&mask);
  cpumask_set_cpu(cpu_pin[i], &mask);

  sched_setaffinity(0, &mask);

  mm->color_num = quanta[i];
  mm->color_cur = 0;
  mm->recolor_flag = REC_NONE; 
  mm->total_ref = 0;
  mm->total_miss = 0;
  mm->recolor_count = sample_stages[smp_processor_id()] + REC_DELAY;
  mm->h_thred = app_qos.high[i];
  mm->l_thred = app_qos.low[i];

#ifdef ALLOC_DEBUG
  printk(KERN_ERR "core %d, %s (pid %d tgid %d colors %d): code %x - %x!\n", 
    smp_processor_id(), current->comm, current->pid, current->tgid, mm->color_num, 
    mm->start_code, mm->end_code);
#endif
}

void release_colors(struct mm_struct *mm) {

  int i, index;
  unsigned long flags;

  for (index = 0; index < nr_apps; index++) {
    if (string_eq(current->comm, apps[index])) break;
  }

  spin_lock_irqsave(&global_hotness.lock, flags);
  for (i = 0; i < mm->color_num; i++) {
    global_hotness.count[mm->my_colors.colors[i]]--;
    /* remote color */
    if (cpu_pin[index] != mm->my_colors.colors[i] / (COLOR_NUM / NUM_CORES))
      global_hotness.remote[mm->my_colors.colors[i]]--;
  }
  spin_unlock_irqrestore(&global_hotness.lock, flags);
}

static int alloc_one_color(struct mm_struct *mm) {

  int color, i, j, index;

  for (index = 0; index < nr_apps; index++) {
    if (string_eq(current->comm, apps[index])) break;
  }

  /* first available color not in mm */
  for (i = 0; i < COLOR_NUM; i++) {
    for (j = 0; j < mm->color_num; j++)
      if (i == mm->my_colors.colors[j]) break;

    if ((j == mm->color_num) && (color_lists[i].num > 0)) break;
  }

  int min;
  unsigned long flags;

  spin_lock_irqsave(&global_hotness.lock, flags);

  if (mm->color_num >= (COLOR_NUM / NUM_CORES)) {
    /* remote color */
    min = global_hotness.count[i];
    color = i;
    for (i = i + 1; i < COLOR_NUM; i++) {
      if ((global_hotness.count[i] < min) && (color_lists[i].num > 0)) {

        for (j = 0; j < mm->color_num; j++)
          if (i == mm->my_colors.colors[j]) break;

        if (j == mm->color_num) {
          min = global_hotness.count[i];
          color = i;
        }
      }
    }
  }
  else {
    min = INT_MAX;
    color = -1;
    for ( ; i < COLOR_NUM; i++) {
      if ((cpu_pin[index] == i / (COLOR_NUM / NUM_CORES)) && 
        (global_hotness.remote[i] < min) && 
        (color_lists[i].num > 0)) {

        for (j = 0; j < mm->color_num; j++)
          if (i == mm->my_colors.colors[j]) break;

        if (j == mm->color_num) {
          min = global_hotness.remote[i];
          color = i;
        }
      }
    }

    if (color == -1) {
      printk(KERN_ERR "cpu %d: local memory shortage\n", cpu_pin[index]);
      BUG();
    }
  }

  spin_unlock_irqrestore(&global_hotness.lock, flags);

  //spin_lock(&mm->cur_lock);

  mm->color_cur = mm->color_num;
  mm->my_colors.colors[mm->color_num] = color;
  mm->color_num++;

  //spin_unlock(&mm->cur_lock);
 
  return color;
}

static int my_vmas_walk(struct mm_struct *mm, int cmd, int num, int *colors);

void move_pages(struct mm_struct *mm) {

  my_vmas_walk(mm, -2, 0, NULL);
  mm->recolor_flag = REC_NONE;

  //TODO: fire timer to check performance gain

#ifdef ALLOC_DEBUG
  printk(KERN_ERR "%s: work done\n", __func__);
#endif
}

enum hrtimer_restart table_scan(struct hrtimer *timer) {

  struct task_struct *task;

  if (current->pid == timer->start_pid) {
    move_pages(current->mm);
  }
  else {
    rcu_read_lock();
    task = find_task_by_vpid(timer->start_pid);
    rcu_read_unlock();

    if (task == NULL) {
      printk(KERN_ERR "%s: task not found\n", __func__);
      return HRTIMER_NORESTART;
    }

    task->mm->recolor_flag = REC_EXP_DONE;
#ifdef ALLOC_DEBUG
    printk(KERN_ERR "%s: work delayed\n", __func__);
#endif
  }

  scanner.working = 0;
  
  return HRTIMER_NORESTART;
}

static void redistribute(struct mm_struct *mm) {

  ktime_t ktime;

  if (my_vmas_walk(mm, -1, 0, NULL)) {
    scanner.working = 0;
    mm->recolor_flag = REC_NONE;
    return;
  }

#ifdef SEL_MOVE
  mm->recolor_flag = REC_NONE;
  scanner.working = 0;
  return;
#endif

#ifdef REDISTRIBUTION
  ktime = ktime_set(0, SCAN_WIN);
  hrtimer_init(&scanner.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
  scanner.timer.function = table_scan;
  hrtimer_start(&scanner.timer, ktime, HRTIMER_MODE_REL_PINNED);

  mm->recolor_flag = REC_EXP_PEND;

#ifdef ALLOC_DEBUG
  if (!hrtimer_active(&scanner.timer))
    printk(KERN_ERR "%s: not active\n", __func__);
  printk(KERN_ERR "%s: work start\n", __func__);
#endif
#endif
}

/* ALLOC_COLORS */
static int expand_colors(struct mm_struct *mm, int num) {

  int i, color[COLORS_ONCE], sig = 0;
  unsigned long flags;

  if (mm->color_num + num > MAX_COLORS) {
    mm->recolor_flag = REC_NONE;
    return 1;
  }

  printk(KERN_ERR "%s: %s color num %d, count %d\n", __func__, current->comm, 
        mm->color_num, num);

  i = num - 1;
  do {
    color[i] = alloc_one_color(mm); 
    i--;
  } while(i >= 0);

  int j;
  for (i = 0; i < nr_apps; i++) {
    if (string_eq(current->comm, apps[i])) break;
  }

#ifdef ALLOC_DEBUG
  if (i == nr_apps) {
    printk(KERN_ERR "%s: error\n", __func__);
    BUG();
  }
#endif

  j = num - 1;
  //spin_lock(&app_locks[i]);

  spin_lock_irqsave(&global_hotness.lock, flags);
  do {
    assignment[i].colors[quanta[i]] = color[j];
    global_hotness.count[color[j]]++;
    if (cpu_pin[i] != color[j] / (COLOR_NUM / NUM_CORES))
      global_hotness.remote[color[j]]++;
    else {
      /* FIXME: not generic, just for the experiment with 8 programs running on 4 cores */
      if (global_hotness.count[color[j]] > 2) sig = 1;
    }
    quanta[i]++;
    j--;
  } while(j >= 0);
  spin_unlock_irqrestore(&global_hotness.lock, flags);

  //spin_unlock(&app_locks[i]);

  spin_lock(&scanner.lock);
  if (scanner.working) {
    spin_unlock(&scanner.lock);
    mm->recolor_flag = REC_NONE;
    printk(KERN_ERR "%s: occupied\n", __func__);
  }
  else {
    scanner.working = 1;
    spin_unlock(&scanner.lock);
    redistribute(mm);
  }

  if (sig) return 2;
  else return 0;
}

/* PICK_VICTIMS */
static void pick_victim_colors(struct mm_struct *mm, int num, int *colors) {

  int index, i, j, app, count = 0;
  unsigned long flags;

  do {
    //spin_lock(&mm->cur_lock);

    for (app = 0; app < nr_apps; app++) {
      if (string_eq(current->comm, apps[app])) break;
    }

    int max;

    spin_lock_irqsave(&global_hotness.lock, flags);

    if (mm->color_num > (COLOR_NUM / NUM_CORES)) {
      /* remote color */
      max = -1;
      for (i = 0; i < mm->color_num; i++) {
        if (cpu_pin[app] != mm->my_colors.colors[i] / (COLOR_NUM / NUM_CORES)) {
          if (global_hotness.count[mm->my_colors.colors[i]] > max) {
            max = global_hotness.count[mm->my_colors.colors[i]];
            index = i;
          }
        }
      }

      colors[count] = mm->my_colors.colors[index];
      global_hotness.count[colors[count]]--;
      global_hotness.remote[colors[count]]--;
    }
    else {
      max = global_hotness.remote[mm->my_colors.colors[0]];
      index = 0;
      for (i = 1; i < mm->color_num; i++) {
        if (global_hotness.remote[mm->my_colors.colors[i]] > max) {
          max = global_hotness.remote[mm->my_colors.colors[i]];
          index = i;
        }
      }

      colors[count] = mm->my_colors.colors[index];
      global_hotness.count[colors[count]]--;
    }

    spin_unlock_irqrestore(&global_hotness.lock, flags);

    for (j = index + 1; j < mm->color_num; j++)
      mm->my_colors.colors[j - 1] = mm->my_colors.colors[j];
    mm->color_num--;
    mm->color_cur = 0;

    //spin_unlock(&mm->cur_lock);

    //spin_lock(&app_locks[app]);

    for (j = index + 1; j < quanta[app]; j++)
      assignment[app].colors[j - 1] = assignment[app].colors[j];
    quanta[app]--;
    hackdata.cur_color[app] = 0;

    //spin_unlock(&app_locks[app]);

    count++;
  } while(count < num); 
}

#ifdef REC_COUNT
static unsigned int hot_count = 0;
#endif

#ifdef SEL_MOVE
static unsigned long flag_mask = (1 << __NR_PAGEFLAGS) - 1;
static int hits[COLOR_NUM];
static int sel_index;
#endif

static unsigned long hot_identify(struct vm_area_struct *vma, pmd_t *pmd,
                                unsigned long addr, unsigned long end,
                                int stage) {

  pte_t *pte;

  pte = pte_offset_map(pmd, addr);
  if (!spin_trylock(&(vma->vm_mm->page_table_lock))) {
#ifdef ALLOC_DEBUG
    printk(KERN_ERR "%s: failed lock\n", __func__);
#endif
    pte_unmap(pte);
    return end;
  }

  do {
    pte_t ptent = *pte;

    if (pte_none(ptent)) continue;
    if (!pte_present(ptent)) continue;

    /* COW entry skipped */
    if (vma->vm_ops == NULL && !pte_write(ptent))
        continue;

    struct page *page = pte_page(ptent);

    if (vma->vm_ops && (atomic_read(&page->_count) != 3))
      continue;

    if (pte_special(ptent)) continue;

    if (stage == -1) {
#ifdef SEL_MOVE
      struct page *new_pg;
      int offset;
      unsigned long pg_flags;
      pte_t entry;
      int color = GET_COLOR(pte_pfn(ptent));
      hits[color]++;
      if (hits[color] == (WAY_ASSOC + 1)) {
        hits[color] = 0;
        
        new_pg = internal_alloc_page(
                      vma->vm_mm->my_colors.colors[vma->vm_mm->color_num - 1 - sel_index]);
        sel_index = (sel_index + 1) % COLORS_TRY;
        if (!new_pg) {
          printk(KERN_ERR "%s: out of memory\n", __func__);
          continue;
        }

        if (vma->vm_ops) {  /* code segment */
          offset = page->index;
          pg_flags = page->flags & flag_mask;

          if (!trylock_page(page)) continue;
          else {
            if (!trylock_page(new_pg)) {
              unlock_page(page);
              printk(KERN_ERR "%s: failed lock new page\n", __func__);
              BUG();
              continue;
            }
          } 

          page_cache_release(page);
          copy_user_highpage(new_pg, page, addr, vma);
          new_pg->private = page->private;
          __SetPageUptodate(new_pg);

          page_remove_rmap(page);
          replace_page_cache_page(page, new_pg, GFP_ATOMIC);
          page_cache_get(new_pg);
          unlock_page(page);
          unlock_page(new_pg);

          list_replace_init(&page->lru, &new_pg->lru);
          page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
          page_cache_release(page);

          page_add_file_rmap(new_pg);
          new_pg->flags = (new_pg->flags & ~flag_mask) | pg_flags;
          entry = mk_pte(new_pg, pte_pgprot(ptent));
          set_pte_at(vma->vm_mm, addr, pte, entry);
        }
        else {
          copy_user_highpage(new_pg, page, addr, vma);
          __SetPageUptodate(new_pg);

          page_remove_rmap(page);
          page_cache_release(page);

          page_add_new_anon_rmap(new_pg, vma, addr);
          entry = mk_pte(new_pg, pte_pgprot(ptent));
          set_pte_at(vma->vm_mm, addr, pte, entry);
        }
        flush_tlb_page(vma, addr);

#ifdef REC_COUNT
        hot_count++;
#endif
      }
#endif

#ifdef REDISTRIBUTION
      /* clear access bit */
      ptent = pte_mkold(ptent);
      set_pte_at(vma->vm_mm, addr, pte, ptent);
      flush_tlb_page(vma, addr);
      continue;
#endif
    }
    else if (stage == -2) {
      /* check access bit */
      if (pte_young(ptent)) {
        ptent = pte_clear_flags(ptent, _PAGE_PRESENT);
        ptent = pte_mkspecial(ptent);
        set_pte_at(vma->vm_mm, addr, pte, ptent);
        flush_tlb_page(vma, addr);

#ifdef REC_COUNT
        hot_count++;
#endif
      }
    }
    else {
      printk(KERN_ERR "%s: bug***************\n", __func__);
      BUG();
    } 
  } while(pte++, addr += PG_SIZE, addr != end);

  spin_unlock(&(vma->vm_mm->page_table_lock));
  pte_unmap(pte - 1);

  return addr;
}

/* lazy recoloring */
/* returns address of the first byte after ptes walked */
static unsigned long my_pte_walk(struct vm_area_struct *vma, pmd_t *pmd,
                                unsigned long addr, unsigned long end, 
                                int num, int *colors) {

  pte_t *pte;
  int i;

  pte = pte_offset_map(pmd, addr);
  if (!spin_trylock(&(vma->vm_mm->page_table_lock))) {
    printk(KERN_ERR "%s: failed lock\n", __func__);
    pte_unmap(pte);
    return end;
  }

  do {
    struct page *page;
    pte_t ptent = *pte;
    int color;

    if (pte_none(ptent)) continue;
    if (!pte_present(ptent)) continue; 

    /* COW entry skipped */
    if (vma->vm_ops == NULL && !pte_write(ptent))
      continue;

    //XXX: maybe use vm_normal_page
    page = pte_page(ptent);

    if (vma->vm_ops && (atomic_read(&page->_count) != 3))
      continue;

    color = GET_COLOR(pte_pfn(ptent));
    for (i = 0; i < num; i++) {
      if (colors[i] == color) break;
    }
    if (i != num) {
      /* zero pfn */
      if (pte_special(ptent)) ;
      else {
        ptent = pte_clear_flags(ptent, _PAGE_PRESENT);
        ptent = pte_mkspecial(ptent);
        set_pte_at(vma->vm_mm, addr, pte, ptent);
        flush_tlb_page(vma, addr);
      }
    }
  } while(pte++, addr += PG_SIZE, addr != end);

  spin_unlock(&(vma->vm_mm->page_table_lock));
  pte_unmap(pte - 1);
  return addr;
}

/* returns address of the first byte after pmds walked */
static unsigned long my_pmd_walk(struct vm_area_struct *vma, pud_t *pud, 
                                unsigned long addr, unsigned long end, 
                                int cmd, int num, int *colors) {

  pmd_t *pmd;
  unsigned long next;

  pmd = pmd_offset(pud, addr);
  do {
    next = pmd_addr_end(addr, end);
    if (pmd_none_or_clear_bad(pmd)) continue;
    if (cmd < 0) next = hot_identify(vma, pmd, addr, next, cmd);
    else next = my_pte_walk(vma, pmd, addr, next, num, colors);
  } while(pmd++, addr = next, addr != end);

  return addr;
}

/* returns address of the first byte after puds walked */
static unsigned long my_pud_walk(struct vm_area_struct *vma, pgd_t *pgd, 
                                unsigned long addr, unsigned long end, 
                                int cmd, int num, int *colors) {

  pud_t *pud;
  unsigned long next;

  pud = pud_offset(pgd, addr);
  do {
    next = pud_addr_end(addr, end);
    if (pud_none_or_clear_bad(pud)) continue;
    next = my_pmd_walk(vma, pud, addr, next, cmd, num, colors);
  } while(pud++, addr = next, addr != end);

  return addr;
}

static int my_vmas_walk(struct mm_struct *mm, int cmd, int num, int *colors) {

  struct vm_area_struct *vma;
  unsigned long addr, next;
  pgd_t *pgd;
  int flag = 0;

  vma = mm->mmap;
  if (!down_read_trylock(&mm->mmap_sem)) {
    //XXX: may need a way to fix this
    printk(KERN_ERR "%s: failed lock\n", __func__);
    return 1;
  }

  for ( ; vma != NULL; vma = vma->vm_next) {
    if (vma->vm_ops) {
      /* XXX: assuming the first vma is code segment */
      if (!flag) flag = 1;
      else continue;
    }
    else if (vma->vm_flags & VM_SHARED) {
      printk(KERN_ERR "%s: shared vma\n", __func__);
      continue;
    }

    addr = vma->vm_start;
    pgd = pgd_offset(mm, addr);
    do {
      next = pgd_addr_end(addr, vma->vm_end);
      if (pgd_none_or_clear_bad(pgd)) continue;
#ifdef SEL_MOVE
      if (cmd < 0) {
        memset(hits, 0, sizeof(int) * COLOR_NUM);
        sel_index = 0;
      }
#endif
      next = my_pud_walk(vma, pgd, addr, next, cmd, num, colors);
    } while(pgd++, addr = next, addr != vma->vm_end);
  }

  up_read(&mm->mmap_sem);

#ifdef REC_COUNT
#ifdef REDISTRIBUTION
  if (cmd == -2) {
    printk(KERN_ERR "%s: %d pages\n", __func__, hot_count);
    hot_count = 0;
  }
#endif

#ifdef SEL_MOVE
  if (cmd == -1) {
    printk(KERN_ERR "%s: %d pages\n", __func__, hot_count);
    hot_count = 0;
  }
#endif
#endif
  return 0;
}

/* anonymous memory from shared libraries (not privated owned) should not be recolored */
static int shrink_colors(struct mm_struct *mm, int num) { 

  int victims[COLOR_NUM];

  if (mm->color_num <= MIN_COLORS) return 1;

  printk(KERN_ERR "%s: %s color num %d, count %d\n", __func__, current->comm, 
    mm->color_num, num);
 
  pick_victim_colors(mm, num, victims);
  my_vmas_walk(mm, 1, num, victims);
  return 0;
}

/* FIXME: not generic, just for the experiment with 8 programs running on 4 cores */
static int giveBack(struct mm_struct *mm, int num) {

  int i, j, app, count = 0;
  unsigned long flags;
  int victims[COLOR_NUM];

  if (mm->color_num > (COLOR_NUM / NUM_CORES)) {
    for (app = 0; app < nr_apps; app++) {
      if (string_eq(current->comm, apps[app])) break;
    }

    spin_lock_irqsave(&global_hotness.lock, flags);

    for (i = 0; i < mm->color_num; i++) {
      if (cpu_pin[app] == mm->my_colors.colors[i] / (COLOR_NUM / NUM_CORES)) continue;

      /* using 2 here since in experiment, each core has 2 apps */
      if (global_hotness.count[mm->my_colors.colors[i]] > 2 && count < num) {
        victims[count] = mm->my_colors.colors[i];
        global_hotness.count[mm->my_colors.colors[i]]--;
        global_hotness.remote[mm->my_colors.colors[i]]--;

        for (j = i + 1; j < mm->color_num; j++)
          mm->my_colors.colors[j - 1] = mm->my_colors.colors[j];
        mm->color_num--;
        mm->color_cur = 0;

        for (j = i + 1; j < quanta[app]; j++)
          assignment[app].colors[j - 1] = assignment[app].colors[j];
        quanta[app]--;
        hackdata.cur_color[app] = 0;

        i--;
        count++;
        if (count == num) break;
      }
    }

    spin_unlock_irqrestore(&global_hotness.lock, flags);

    if (count == 0) return 0;

#ifdef ALLOC_DEBUG
    printk(KERN_ERR "%s: %s color num %d, count %d\n", __func__, current->comm, 
      mm->color_num, count);
#endif

    my_vmas_walk(mm, 1, count, victims);

    j = 1;
    for (i = 0; i < COLOR_NUM; i++) 
      if (global_hotness.count[i] > 2) j = 2;

    return j;
  }

  return 0;
}

/* called by schedule */
int mm_recoloring(struct mm_struct *mm, int isExpand) {

  if (isExpand == 1) return expand_colors(mm, COLORS_TRY);
  else if (isExpand == 0) return shrink_colors(mm, COLORS_TRY);
  /* FIXME: not generic, just for the experiment with 8 programs running on 4 cores */
  else return giveBack(mm, COLORS_TRY);
}

enum hrtimer_restart do_sample(struct hrtimer *timer) {

  ktime_t ktime;
  sample_stages[smp_processor_id()]++;
  ktime = ktime_set(SAMPLE_PERIOD, 0);
  hrtimer_forward_now(timer, ktime);
  return HRTIMER_RESTART;
}

void inst_read(struct task_struct *task) {

  unsigned int low, high, ref, miss;
  int i;

  if (ipc_sig[smp_processor_id()]) {
    /* assuming LLC counters doesn't overflow with 32 bits */
    rdmsr(0xC1, miss, high);
    rdmsr(0xC2, ref, high);

    rdmsr(0xC3, low, high);

    for (i = 0; i < nr_apps; i++) {
      if (string_eq(task->comm, apps[i])) break;
    }

    if ((unsigned int)0xFFFFFFFF - app_miss_l[i] < miss)
      app_miss_h[i]++;
    app_miss_l[i] += miss;

    if ((unsigned int)0xFFFFFFFF - app_ref_l[i] < ref)
      app_ref_h[i]++;
    app_ref_l[i] += ref;

    if ((unsigned int)0xFFFFFFFF - app_inst_l[i] < low)
      app_inst_h[i]++;
    app_inst_l[i] += low;
    app_inst_h[i] += high;
  }
}

enum hrtimer_restart ipc_count(struct hrtimer *timer) {

  ktime_t ktime;
  int cpu = smp_processor_id();

  if (!ipc_sig[cpu]) {
    wrmsr(0xC3, 0, 0);

    /* get result after some time */
    ktime = ktime_set(TEST_TIME, 0);
    hrtimer_forward_now(timer, ktime);
    ipc_sig[cpu] = 1;

    /* periodic sampling */
    ktime = ktime_set(SAMPLE_PERIOD, 0);
    hrtimer_init(&sample_timer[cpu], CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
    sample_timer[cpu].function = do_sample;
    hrtimer_start(&sample_timer[cpu], ktime, HRTIMER_MODE_REL_PINNED);

    printk(KERN_ERR "%s: first stage\n", __func__);

    return HRTIMER_RESTART;
  }
  else {
    hrtimer_cancel(&sample_timer[cpu]);

    ipc_sig[cpu] = 0;

    printk(KERN_ERR "%s: second stage\n", __func__);

    return HRTIMER_NORESTART;
  }
}

int fire_timer(void *arg) {

  struct cpumask mask;
  unsigned int cpu = (unsigned int)arg;
  ktime_t ktime;

  /* pin to cpu */
  cpumask_clear(&mask);
  cpumask_set_cpu(cpu, &mask);

  sched_setaffinity(0, &mask);

  /* when next time gets scheduled, runs on designated cpu */
  while(ipc_apps != nr_apps) schedule();

  if (smp_processor_id() != cpu) {
    printk(KERN_ERR "Fails to fire timer %d!\n", cpu);
    return 0;
  }

  ipc_sig[smp_processor_id()] = 0;

  /* install hrtimer */
  /* start counting after 1 min */
  ktime = ktime_set(60, 0);
  hrtimer_init(&ipc_timer[cpu], CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
  ipc_timer[cpu].function = ipc_count;
  hrtimer_start(&ipc_timer[cpu], ktime, HRTIMER_MODE_REL_PINNED);

  return 0;
}

/* ioctl entry point, debugging tool */
int debug_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

  struct task_struct *p;
  struct mm_struct *mm;
  int index, i;
  struct color_set *set_ptr;

  if (cmd == MY_CHECK_ALL) {
    read_lock(&tasklist_lock);

    for_each_process(p) {
      mm = p->mm;
      /* ignore kernel threads and irrelevant processes */
      if (mm != NULL && mm->color_num > 0) {
        printk(KERN_ERR "%s (pid %d, tgid %d, mm addr %x, colors %d): ", p->comm,
          p->pid, p->tgid, (unsigned int)mm, mm->color_num);

        index = 0;
        set_ptr = &(mm->my_colors);

        do {
          printk(KERN_ERR "%d ", set_ptr->colors[index]);
          index++;
        } while(index < mm->color_num);

        printk(KERN_ERR " current: %d\n", mm->color_cur);

        printk(KERN_ERR "QoS: %d %d\n", mm->h_thred, mm->l_thred);
      }
    }

    read_unlock(&tasklist_lock);
  }
  else if (cmd == MY_CHECK_ONE) {
    rcu_read_lock();

    /* look up thread by pid */
    p = find_task_by_vpid((pid_t)arg);

    rcu_read_unlock();

    if (p == NULL) {
      printk(KERN_ERR "No process found!\n");
    }
    else if (p->mm == NULL) {
      printk(KERN_ERR "PID belongs to kernel thread!\n");
    }
    else if (p->mm->color_num == 0) {
      printk(KERN_ERR "No color assigned to it!\n");
    }
    else {
      mm = p->mm;
      index = 0;
      set_ptr = &(mm->my_colors);

      printk(KERN_ERR "Process %s: ", p->comm);
      do {
        printk(KERN_ERR "%d ", set_ptr->colors[index]);
        index++;
      } while(index < mm->color_num);

      printk(KERN_ERR " current: %d\n", mm->color_cur);

      printk(KERN_ERR "QoS: %d %d\n", mm->h_thred, mm->l_thred);
    }
  }
  else if (cmd == MY_CHECK_RESERVE) {
    printk(KERN_ERR "Color statistic: ");

    for (i = 0; i < COLOR_NUM; i++)
      printk(KERN_ERR "color %d (%d) ", i, (int)(color_lists[i].num));

    printk(KERN_ERR "\n");
  }
  else if (cmd == MY_CHECK_FILE) {
    printk(KERN_ERR "assignments: ");

    for (i = 0; i < nr_apps; i++) {
      printk(KERN_ERR "%s (%d): ", apps[i], quanta[i]);

      index = 0;
      set_ptr = &assignment[i];
      do {
        printk(KERN_ERR "%d ", set_ptr->colors[index]);
        index++;
      } while(index < quanta[i]);

      printk(KERN_ERR " current: %d\n", hackdata.cur_color[i]);

      printk(KERN_ERR "QoS: %d %d\n", app_qos.high[i], app_qos.low[i]);
    }
  }
  else if (cmd == MY_CHECK_IPC) {
    printk(KERN_ERR "IPCs: ");

    for (i = 0; i < nr_apps; i++)
      printk(KERN_ERR "app %s, inst %u %u\n", apps[i], app_inst_h[i], 
        app_inst_l[i]);

    for (i = 0; i < nr_apps; i++)
      printk(KERN_ERR "app %s, miss %u %u, ref %u %u\n", apps[i], app_miss_h[i], 
        app_miss_l[i], app_ref_h[i], app_ref_l[i]);
  }
  else if (cmd == MY_CHECK_HOT) {
    printk(KERN_ERR "Hotness: ");

    for (i = 0; i < COLOR_NUM; i++)
      printk(KERN_ERR "color %d: %d remote %d\n", i, global_hotness.count[i], 
        global_hotness.remote[i]);
  }
  else {
    printk(KERN_ERR "Invalid input command!\n");
    return -1;
  }

  return 0;
}


module_init(alloc_init);
module_exit(alloc_cleanup);

/* vi: set et sw=2 sts=2: */
