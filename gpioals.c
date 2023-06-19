// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: © 2023 Alexander König <alex@lisas.de>

// define early to avoid redefinition warnings
#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/cdev.h>
#include <linux/circ_buf.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/types.h>

#define GPIOALS_IDLE 0
#define GPIOALS_DISCHARGE 1
#define GPIOALS_MEASURING 2

#define GPIOALS_COMMAND_CANCEL 0
#define GPIOALS_COMMAND_ARM 1
#define GPIOALS_COMMAND_MEASURE 2
#define GPIOALS_COMMAND_STATISTICS 3

static int gpioals_gpio_pin = 10;
static unsigned int gpioals_irq;

static int gpioals_state = GPIOALS_IDLE;
static int gpioals_opened = 0;
static dev_t gpioals_dev = 0;
static struct class *gpioals_dev_class;
static struct cdev gpioals_cdev;
static int irq_ctr = 0;
static int unexpected_irq_ctr = 0;
static int dropped = 0;

struct circ_buf *rx_buf;
static DECLARE_WAIT_QUEUE_HEAD(rx_queue);
static struct mutex rx_read_lock;

struct als_measurement {
  ktime_t timestamp;
  s64 ns;
};

typedef struct als_measurement als_measurement_t;

#define RX_BUF_COUNT 64
#define RX_BUF_SIZE RX_BUF_COUNT * sizeof(als_measurement_t)

static ktime_t gpioals_measurement_start;

static irqreturn_t gpioals_irq_handler(int irq, void *dev_id) {
  static unsigned long flags = 0;
  static ktime_t gpioals_measurement_end;
  static ktime_t gpioals_measured_diff;
  static s64 measured_diff_in_ns;

  local_irq_save(flags);

  if (gpioals_state == GPIOALS_MEASURING) {
    gpioals_measurement_end = ktime_get();
    gpioals_measured_diff = ktime_sub(gpioals_measurement_end, gpioals_measurement_start);
    measured_diff_in_ns = ktime_to_ns(gpioals_measured_diff);

    gpioals_state = GPIOALS_IDLE;

    if (CIRC_SPACE(rx_buf->head, rx_buf->tail, RX_BUF_SIZE) > 0) {
      als_measurement_t *measure_ptr = (als_measurement_t *) &rx_buf->buf[rx_buf->head];
      measure_ptr->timestamp = gpioals_measurement_end;
      measure_ptr->ns = measured_diff_in_ns;

      smp_store_release(&rx_buf->head, ((rx_buf->head + sizeof(als_measurement_t)) & (RX_BUF_SIZE - 1)));

      wake_up_all(&rx_queue);
    } else {
      dropped++;
    }

    irq_ctr++;
  } else {
    unexpected_irq_ctr++;
  }

  local_irq_restore(flags);

  return IRQ_HANDLED;
}

// file ops
static ssize_t gpioals_read(struct file *, char *, size_t, loff_t *);
static ssize_t gpioals_write(struct file *, const char *, size_t, loff_t *);
static int gpioals_open(struct inode *, struct file *);
static int gpioals_release(struct inode *, struct file *);

static struct file_operations gpioals_fops = {
  .owner          = THIS_MODULE,
  .read           = gpioals_read,
  .write          = gpioals_write,
  .open           = gpioals_open,
  .release        = gpioals_release,
};

// read from char dev
static ssize_t gpioals_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset) {
  int ret = -EFAULT;
  int bytes = 0;
  char *read_ptr;

  if (len < sizeof(als_measurement_t)) {
    return -EINVAL;
  }

  mutex_lock(&rx_read_lock);
  ret = wait_event_interruptible(rx_queue, CIRC_CNT(rx_buf->head, rx_buf->tail, RX_BUF_SIZE) > 0);
  if (ret) {
    goto read_terminate;
  }

  bytes = min_t(int, len, CIRC_CNT_TO_END(rx_buf->head, rx_buf->tail, RX_BUF_SIZE));
  read_ptr = &rx_buf->buf[rx_buf->tail];
  if (copy_to_user(buffer, read_ptr, bytes) > 0) {
    goto read_terminate;
  }

  smp_store_release(&rx_buf->tail, (rx_buf->tail + bytes) & (RX_BUF_SIZE - 1));
  *offset += bytes;

  wake_up_all(&rx_queue);
  ret = bytes;

read_terminate:
  mutex_unlock(&rx_read_lock);

  return ret;
}

// trigger measurement via char dev
static ssize_t gpioals_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset) {
  uint8_t command = 2;

  if (len > 0) {
    if (copy_from_user(&command, buffer, 1) > 0) {
      pr_err("failed to read command from userspace\n");
      return -EFAULT;
    }

    if (command == GPIOALS_COMMAND_CANCEL) {
      gpioals_state = GPIOALS_IDLE;
      gpio_direction_input(gpioals_gpio_pin);
    } else if (command == GPIOALS_COMMAND_ARM) {
      gpioals_state = GPIOALS_DISCHARGE;
      gpio_direction_output(gpioals_gpio_pin, 0);
    } else if (command == GPIOALS_COMMAND_MEASURE) {
      gpioals_state = GPIOALS_MEASURING;
      gpio_direction_input(gpioals_gpio_pin);
      gpioals_measurement_start = ktime_get();
    } else if (command == GPIOALS_COMMAND_STATISTICS) {
      pr_info("detected %d expected interrupts (%d dropped) and %d unexpected so far.\n", irq_ctr, dropped, unexpected_irq_ctr);
    } else {
      pr_err("invalid command: %u\n", (uint) command);
    }
    return 1;
  }

  return 0;
}

// open the char dev
static int gpioals_open(struct inode *inode, struct file *file) {
  if (gpioals_opened) {
    return -EBUSY;
  }
  gpioals_opened++;
  try_module_get(THIS_MODULE);
  return 0;
}

// release the char dev
static int gpioals_release(struct inode *inode, struct file *file) {
  gpioals_state = GPIOALS_IDLE;
  gpio_direction_input(gpioals_gpio_pin);

  gpioals_opened--;
  module_put(THIS_MODULE);
  return 0;
}

// setup
static int __init gpioals_driver_init(void) {
  if (alloc_chrdev_region(&gpioals_dev, 0, 1, "gpioals_chrdev") < 0) {
    pr_err("failed to allocate chrdev numbers\n");
    goto release_chrdev;
  }

  cdev_init(&gpioals_cdev, &gpioals_fops);

  if (cdev_add(&gpioals_cdev, gpioals_dev, 1) < 0) {
    pr_err("failed to register cdev\n");
    goto release_cdev;
  }

  if (IS_ERR(gpioals_dev_class = class_create(THIS_MODULE, "gpioals_class"))) {
    pr_err("failed to create gpioals device class\n");
    goto release_class;
  }

  if (IS_ERR(device_create(gpioals_dev_class, NULL, gpioals_dev, NULL, "gpioals_device"))) {
    pr_err( "failed to create gpioals device\n");
    goto release_device;
  }

  if (gpio_is_valid(gpioals_gpio_pin) == false) {
    pr_err("invalid gpio pin: %d\n", gpioals_gpio_pin);
    goto release_device;
  }

  if (gpio_request(gpioals_gpio_pin, "gpioals_gpio_pin") < 0) {
    pr_err("failed to request gpio: %d\n", gpioals_gpio_pin);
    goto release_gpio;
  }

  gpio_direction_input(gpioals_gpio_pin);

  //setup irq
  gpioals_irq = gpio_to_irq(gpioals_gpio_pin);

  if (request_irq(gpioals_irq, (void *) gpioals_irq_handler, IRQF_TRIGGER_RISING, "gpioals_device", NULL)) {
    pr_err("failed to register irq\n");
    goto release_gpio;
  }

  rx_buf = kmalloc(sizeof(struct circ_buf), GFP_KERNEL);

  if (!rx_buf) {
    pr_err("failed to allocate circular buffer\n");
    goto release_irq;
  }

  rx_buf->buf = kmalloc(RX_BUF_SIZE, GFP_KERNEL);

  if (!rx_buf->buf) {
    pr_err("failed to allocate memory for measurement storage\n");
    goto release_rx_buf;
  }

  rx_buf->head = rx_buf->tail = 0;

  mutex_init(&rx_read_lock);

  pr_info("initialization completed successfully, using GPIO %d - (%u/%u))\n", gpioals_gpio_pin, MAJOR(gpioals_dev), MINOR(gpioals_dev));
  return 0;

release_rx_buf:
  kfree(rx_buf);
release_irq:
  free_irq(gpioals_irq, NULL);
release_gpio:
  gpio_free(gpioals_gpio_pin);
release_device:
  device_destroy(gpioals_dev_class, gpioals_dev);
release_class:
  class_destroy(gpioals_dev_class);
release_cdev:
  cdev_del(&gpioals_cdev);
release_chrdev:
  unregister_chrdev_region(gpioals_dev, 1);

  return -1;
}

// cleanup
static void __exit gpioals_driver_exit(void) {
  mutex_destroy(&rx_read_lock);
  kfree(rx_buf->buf);
  kfree(rx_buf);
  free_irq(gpioals_irq, NULL);
  gpio_free(gpioals_gpio_pin);
  device_destroy(gpioals_dev_class, gpioals_dev);
  class_destroy(gpioals_dev_class);
  cdev_del(&gpioals_cdev);
  unregister_chrdev_region(gpioals_dev, 1);
  pr_info("exit completed\n");
}

module_init(gpioals_driver_init);
module_exit(gpioals_driver_exit);
module_param(gpioals_gpio_pin, int, 0444);

MODULE_PARM_DESC(gpioals_gpio_pin, "The GPIO pin to use to measure ambient light levels. Default is \'10\'.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander König <alex@lisas.de>");
MODULE_DESCRIPTION("Implement an ambient light sensor through GPIO");
MODULE_VERSION("0.1");
