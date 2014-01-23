/*
 * USB Skeleton driver - 2.2
 *
 * Copyright (C) 2001-2004 Greg Kroah-Hartman (greg@kroah.com)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * This driver is based on the 2.6.3 version of drivers/usb/usb-skeleton.c
 * but has been rewritten to be easier to read and use.
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include <linux/crc-itu-t.h>

#include "usb_test.h"
#include "rt73usb.h"
#include "usb_test_hw.h"

/* Define these values to match your devices */
#define USB_SKEL_VENDOR_ID	0x148f
#define USB_SKEL_PRODUCT_ID	0x2573

/* table of devices that work with this driver */
static const struct usb_device_id skel_table[] = {
	{ USB_DEVICE(USB_SKEL_VENDOR_ID, USB_SKEL_PRODUCT_ID) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, skel_table);


/* Get a minor range for your devices from the usb maintainer */
#define USB_SKEL_MINOR_BASE	192

/* our private defines. if this grows any larger, use your own .h file */
#define MAX_TRANSFER		(PAGE_SIZE - 512)
/* MAX_TRANSFER is chosen so that the VM is not stressed by
   allocations > PAGE_SIZE and the number of packets in a page
   is an integer 512 is the largest possible packet on EHCI */
#define WRITES_IN_FLIGHT	8
/* arbitrarily chosen */

/* Structure to hold all of our device specific stuff */
struct usb_skel {
	struct usb_device	*udev;			/* the usb device for this device */
	struct usb_interface	*interface;		/* the interface for this device */
	struct semaphore	limit_sem;		/* limiting the number of writes in progress */
	struct usb_anchor	submitted;		/* in case we need to retract our submissions */
	struct urb		*bulk_in_urb;		/* the urb to read data with */
	unsigned char           *bulk_in_buffer;	/* the buffer to receive data */
	size_t			bulk_in_size;		/* the size of the receive buffer */
	size_t			bulk_in_filled;		/* number of bytes in the buffer */
	size_t			bulk_in_copied;		/* already copied to user space */
	__u8			bulk_in_endpointAddr;	/* the address of the bulk in endpoint */
	__u8			bulk_out_endpointAddr;	/* the address of the bulk out endpoint */
	int			errors;			/* the last request tanked */
	bool			ongoing_read;		/* a read is going on */
	spinlock_t		err_lock;		/* lock for errors */
	struct kref		kref;
	struct mutex		io_mutex;		/* synchronize I/O with disconnect */
	wait_queue_head_t	bulk_in_wait;		/* to wait for an ongoing read */
};
#define to_skel_dev(d) container_of(d, struct usb_skel, kref)

static struct usb_driver skel_driver;
static void skel_draw_down(struct usb_skel *dev);

static void skel_delete(struct kref *kref)
{
	struct usb_skel *dev = to_skel_dev(kref);

	usb_free_urb(dev->bulk_in_urb);
	usb_put_dev(dev->udev);
	kfree(dev->bulk_in_buffer);
	kfree(dev);
}

static int skel_open(struct inode *inode, struct file *file)
{
		
	struct usb_skel *dev;
	struct usb_interface *interface;
	int subminor;
	int retval = 0;

	printk(KERN_INFO "USB_test open. \n");	

	subminor = iminor(inode);

	interface = usb_find_interface(&skel_driver, subminor);
	if (!interface) {
		pr_err("%s - error, can't find device for minor %d\n",
			__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}

	dev = usb_get_intfdata(interface);
	if (!dev) {
		retval = -ENODEV;
		goto exit;
	}

	retval = usb_autopm_get_interface(interface);
	if (retval)
		goto exit;

	/* increment our usage count for the device */
	kref_get(&dev->kref);

	/* save our object in the file's private structure */
	file->private_data = dev;

exit:
	return retval;
}

static int skel_release(struct inode *inode, struct file *file)
{
	struct usb_skel *dev;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* allow the device to be autosuspended */
	mutex_lock(&dev->io_mutex);
	if (dev->interface)
		usb_autopm_put_interface(dev->interface);
	mutex_unlock(&dev->io_mutex);

	/* decrement the count on our device */
	kref_put(&dev->kref, skel_delete);
	return 0;
}

static int skel_flush(struct file *file, fl_owner_t id)
{
	struct usb_skel *dev;
	int res;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* wait for io to stop */
	mutex_lock(&dev->io_mutex);
	skel_draw_down(dev);

	/* read out errors, leave subsequent opens a clean slate */
	spin_lock_irq(&dev->err_lock);
	res = dev->errors ? (dev->errors == -EPIPE ? -EPIPE : -EIO) : 0;
	dev->errors = 0;
	spin_unlock_irq(&dev->err_lock);

	mutex_unlock(&dev->io_mutex);

	return res;
}

static void skel_read_bulk_callback(struct urb *urb)
{
	struct usb_skel *dev;

	dev = urb->context;

	spin_lock(&dev->err_lock);
	/* sync/async unlink faults aren't errors */
	if (urb->status) {
		if (!(urb->status == -ENOENT ||
		    urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev,
				"%s - nonzero write bulk status received: %d\n",
				__func__, urb->status);

		dev->errors = urb->status;
	} else {
		dev->bulk_in_filled = urb->actual_length;
	}
	dev->ongoing_read = 0;
	spin_unlock(&dev->err_lock);

	wake_up_interruptible(&dev->bulk_in_wait);
}

static int skel_do_read_io(struct usb_skel *dev, size_t count)
{
	int rv;

	/* prepare a read */
	usb_fill_bulk_urb(dev->bulk_in_urb,
			dev->udev,
			usb_rcvbulkpipe(dev->udev,
				dev->bulk_in_endpointAddr),
			dev->bulk_in_buffer,
			min(dev->bulk_in_size, count),
			skel_read_bulk_callback,
			dev);
	/* tell everybody to leave the URB alone */
	spin_lock_irq(&dev->err_lock);
	dev->ongoing_read = 1;
	spin_unlock_irq(&dev->err_lock);

	/* submit bulk in urb, which means no data to deliver */
	dev->bulk_in_filled = 0;
	dev->bulk_in_copied = 0;

	/* do it */
	rv = usb_submit_urb(dev->bulk_in_urb, GFP_KERNEL);
	if (rv < 0) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting read urb, error %d\n",
			__func__, rv);
		rv = (rv == -ENOMEM) ? rv : -EIO;
		spin_lock_irq(&dev->err_lock);
		dev->ongoing_read = 0;
		spin_unlock_irq(&dev->err_lock);
	}

	return rv;
}

static ssize_t skel_read(struct file *file, char *buffer, size_t count,
			 loff_t *ppos)
{
	struct usb_skel *dev;
	int rv;
	bool ongoing_io;

	dev = file->private_data;

	/* if we cannot read at all, return EOF */
	if (!dev->bulk_in_urb || !count)
		return 0;

	/* no concurrent readers */
	rv = mutex_lock_interruptible(&dev->io_mutex);
	if (rv < 0)
		return rv;

	if (!dev->interface) {		/* disconnect() was called */
		rv = -ENODEV;
		goto exit;
	}

	/* if IO is under way, we must not touch things */
retry:
	spin_lock_irq(&dev->err_lock);
	ongoing_io = dev->ongoing_read;
	spin_unlock_irq(&dev->err_lock);

	if (ongoing_io) {
		/* nonblocking IO shall not wait */
		if (file->f_flags & O_NONBLOCK) {
			rv = -EAGAIN;
			goto exit;
		}
		/*
		 * IO may take forever
		 * hence wait in an interruptible state
		 */
		rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
		if (rv < 0)
			goto exit;
	}

	/* errors must be reported */
	rv = dev->errors;
	if (rv < 0) {
		/* any error is reported once */
		dev->errors = 0;
		/* to preserve notifications about reset */
		rv = (rv == -EPIPE) ? rv : -EIO;
		/* report it */
		goto exit;
	}

	/*
	 * if the buffer is filled we may satisfy the read
	 * else we need to start IO
	 */

	if (dev->bulk_in_filled) {
		/* we had read data */
		size_t available = dev->bulk_in_filled - dev->bulk_in_copied;
		size_t chunk = min(available, count);

		if (!available) {
			/*
			 * all data has been used
			 * actual IO needs to be done
			 */
			rv = skel_do_read_io(dev, count);
			if (rv < 0)
				goto exit;
			else
				goto retry;
		}
		/*
		 * data is available
		 * chunk tells us how much shall be copied
		 */

		if (copy_to_user(buffer,
				 dev->bulk_in_buffer + dev->bulk_in_copied,
				 chunk))
			rv = -EFAULT;
		else
			rv = chunk;

		dev->bulk_in_copied += chunk;

		/*
		 * if we are asked for more than we have,
		 * we start IO but don't wait
		 */
		if (available < count)
			skel_do_read_io(dev, count - chunk);
	} else {
		/* no data in the buffer */
		rv = skel_do_read_io(dev, count);
		if (rv < 0)
			goto exit;
		else if (!(file->f_flags & O_NONBLOCK))
			goto retry;
		rv = -EAGAIN;
	}
exit:
	mutex_unlock(&dev->io_mutex);
	return rv;
}

static void skel_write_bulk_callback(struct urb *urb)
{
	struct usb_skel *dev;

	dev = urb->context;

	/* sync/async unlink faults aren't errors */
	if (urb->status) {
		if (!(urb->status == -ENOENT ||
		    urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev,
				"%s - nonzero write bulk status received: %d\n",
				__func__, urb->status);

		spin_lock(&dev->err_lock);
		dev->errors = urb->status;
		spin_unlock(&dev->err_lock);
	}

	/* free up our allocated buffer */
	usb_free_coherent(urb->dev, urb->transfer_buffer_length,
			  urb->transfer_buffer, urb->transfer_dma);
	up(&dev->limit_sem);
}

static ssize_t skel_write(struct file *file, const char *user_buffer,
			  size_t count, loff_t *ppos)
{
	struct usb_skel *dev;
	int retval = 0;
	struct urb *urb = NULL;
	char *buf = NULL;
	size_t writesize = min(count, (size_t)MAX_TRANSFER);

	dev = file->private_data;

	/* verify that we actually have some data to write */
	if (count == 0)
		goto exit;

	/*
	 * limit the number of URBs in flight to stop a user from using up all
	 * RAM
	 */
	if (!(file->f_flags & O_NONBLOCK)) {
		if (down_interruptible(&dev->limit_sem)) {
			retval = -ERESTARTSYS;
			goto exit;
		}
	} else {
		if (down_trylock(&dev->limit_sem)) {
			retval = -EAGAIN;
			goto exit;
		}
	}

	spin_lock_irq(&dev->err_lock);
	retval = dev->errors;
	if (retval < 0) {
		/* any error is reported once */
		dev->errors = 0;
		/* to preserve notifications about reset */
		retval = (retval == -EPIPE) ? retval : -EIO;
	}
	spin_unlock_irq(&dev->err_lock);
	if (retval < 0)
		goto error;

	/* create a urb, and a buffer for it, and copy the data to the urb */
	urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!urb) {
		retval = -ENOMEM;
		goto error;
	}

	buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
				 &urb->transfer_dma);
	if (!buf) {
		retval = -ENOMEM;
		goto error;
	}

	if (copy_from_user(buf, user_buffer, writesize)) {
		retval = -EFAULT;
		goto error;
	}

	/* this lock makes sure we don't submit URBs to gone devices */
	mutex_lock(&dev->io_mutex);
	if (!dev->interface) {		/* disconnect() was called */
		mutex_unlock(&dev->io_mutex);
		retval = -ENODEV;
		goto error;
	}

	/* initialize the urb properly */
	usb_fill_bulk_urb(urb, dev->udev,
			  usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
			  buf, writesize, skel_write_bulk_callback, dev);
	urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	usb_anchor_urb(urb, &dev->submitted);

	/* send the data out the bulk port */
	retval = usb_submit_urb(urb, GFP_KERNEL);
	mutex_unlock(&dev->io_mutex);
	if (retval) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		goto error_unanchor;
	}

	/*
	 * release our reference to this urb, the USB core will eventually free
	 * it entirely
	 */
	usb_free_urb(urb);


	return writesize;

error_unanchor:
	usb_unanchor_urb(urb);
error:
	if (urb) {
		usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
		usb_free_urb(urb);
	}
	up(&dev->limit_sem);

exit:
	return retval;
}

static const struct file_operations skel_fops = {
	.owner =	THIS_MODULE,
	.read =		skel_read,
	.write =	skel_write,
	.open =		skel_open,
	.release =	skel_release,
	.flush =	skel_flush,
	.llseek =	noop_llseek,
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
static struct usb_class_driver skel_class = {
	.name =		"skel%d",
	.fops =		&skel_fops,
	.minor_base =	USB_SKEL_MINOR_BASE,
};

static int skel_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_skel *dev;
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	size_t buffer_size;
	int i;
	int retval = -ENOMEM;

	/* allocate memory for our device state and initialize it */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&interface->dev, "Out of memory\n");
		goto error;
	}
	kref_init(&dev->kref);
	sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
	mutex_init(&dev->io_mutex);
	spin_lock_init(&dev->err_lock);
	init_usb_anchor(&dev->submitted);
	init_waitqueue_head(&dev->bulk_in_wait);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	/* set up the endpoint information */
	/* use only the first bulk-in and bulk-out endpoints */
	iface_desc = interface->cur_altsetting;
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (!dev->bulk_in_endpointAddr &&
		    usb_endpoint_is_bulk_in(endpoint)) {
			/* we found a bulk in endpoint */
			buffer_size = usb_endpoint_maxp(endpoint);
			dev->bulk_in_size = buffer_size;
			dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
			dev->bulk_in_buffer = kmalloc(buffer_size, GFP_KERNEL);
			if (!dev->bulk_in_buffer) {
				dev_err(&interface->dev,
					"Could not allocate bulk_in_buffer\n");
				goto error;
			}
			dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
			if (!dev->bulk_in_urb) {
				dev_err(&interface->dev,
					"Could not allocate bulk_in_urb\n");
				goto error;
			}
		}

		if (!dev->bulk_out_endpointAddr &&
		    usb_endpoint_is_bulk_out(endpoint)) {
			/* we found a bulk out endpoint */
			dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
		}
	}
	if (!(dev->bulk_in_endpointAddr && dev->bulk_out_endpointAddr)) {
		dev_err(&interface->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, dev);

	/* we can register the device now, as it is ready */
	retval = usb_register_dev(interface, &skel_class);
	if (retval) {
		/* something prevented us from registering this driver */
		dev_err(&interface->dev,
			"Not able to get a minor for this device.\n");
		usb_set_intfdata(interface, NULL);
		goto error;
	}

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev,
		 "UT: USB Skeleton device now attached to USBSkel-%d",
		 interface->minor);
	return 0;

error:
	if (dev)
		/* this frees allocated memory */
		kref_put(&dev->kref, skel_delete);
	return retval;
}

/**************** UT: necessary rt73usb operations *************/
/*
 * Firmware functions
 */
static char *rt73usb_get_firmware_name(struct rt2x00_dev *rt2x00dev)
{
	return FIRMWARE_RT2571;
}

static int rt73usb_check_firmware(struct rt2x00_dev *rt2x00dev,
				  const u8 *data, const size_t len)
{

	u16 fw_crc;
	u16 crc;	

	// Only support 2kb firmware files.
	if (len != 2048)
		return FW_BAD_LENGTH;

	// The last 2 bytes in the firmware array are the crc checksum itself,
	// this means that we should never pass those 2 bytes to the crc
	// algorithm.
	fw_crc = (data[len - 2] << 8 | data[len - 1]);

	//Use the crc itu-t algorithm.
	crc = crc_itu_t(0, data, len - 2);
	crc = crc_itu_t_byte(crc, 0);
	crc = crc_itu_t_byte(crc, 0);

	return (fw_crc == crc) ? FW_OK : FW_BAD_CRC;

}

static int rt73usb_load_firmware(struct rt2x00_dev *rt2x00dev,
				 const u8 *data, const size_t len)
{	
	unsigned int i;
	int retval;
	u32 reg;

	// Wait for stable hardware.
	for (i = 0; i < 100; i++) {
		ut_register_read(rt2x00dev, MAC_CSR0, &reg);
		if (reg)
			break;
		msleep(1);
	}

	if (!reg) {
		rt2x00_err(rt2x00dev, "Unstable hardware\n");
		return -EBUSY;
	}

	//Write firmware to device.
	ut_register_multiwrite(rt2x00dev, FIRMWARE_IMAGE_BASE, data, len);

	// Send firmware request to device to load firmware,
	// we need to specify a long timeout time.
	retval = ut_vendor_request_sw(rt2x00dev, USB_DEVICE_MODE,
					     0, USB_MODE_FIRMWARE,
					     REGISTER_TIMEOUT_FIRMWARE);
	if (retval < 0) {
		printk(KERN_WARNING "UT: Failed to write Firmware to device. \n");
		return retval;
	}

	return 0;
}

/********************/
static int rt73usb_validate_eeprom(struct rt2x00_dev *rt2x00dev)
{
	int retval;
	u16 word;
	u8 *mac;
	s8 value;

	printk(KERN_INFO "UT: reading EEPROM at: 0x %x ...\n", *(rt2x00dev->eeprom));
	retval = ut_eeprom_read(rt2x00dev, rt2x00dev->eeprom, EEPROM_SIZE);
	printk(KERN_INFO "UT: finished reading EEPROM --status: %d \n", retval);

	mac = rt2x00_eeprom_addr(rt2x00dev, EEPROM_MAC_ADDR_0);
	printk(KERN_INFO "UT: MAC address: %pM \n", mac); 
	
	rt2x00_eeprom_read(rt2x00dev, EEPROM_ANTENNA, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_ANTENNA_NUM, 2);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_TX_DEFAULT, ANTENNA_B);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_RX_DEFAULT, ANTENNA_B);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_FRAME_TYPE, 0);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_DYN_TXAGC, 0);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_HARDWARE_RADIO, 0);
		rt2x00_set_field16(&word, EEPROM_ANTENNA_RF_TYPE, RF5226);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_ANTENNA, word);
		rt2x00_eeprom_dbg(rt2x00dev, "Antenna: 0x%04x\n", word);
	}
	
	rt2x00_eeprom_read(rt2x00dev, EEPROM_NIC, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_NIC_EXTERNAL_LNA, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_NIC, word);
		rt2x00_eeprom_dbg(rt2x00dev, "NIC: 0x%04x\n", word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_LED, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_RDY_G, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_RDY_A, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_ACT, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_GPIO_0, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_GPIO_1, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_GPIO_2, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_GPIO_3, 0);
		rt2x00_set_field16(&word, EEPROM_LED_POLARITY_GPIO_4, 0);
		rt2x00_set_field16(&word, EEPROM_LED_LED_MODE, LED_MODE_DEFAULT);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_LED, word);
		rt2x00_eeprom_dbg(rt2x00dev, "Led: 0x%04x\n", word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_FREQ, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_FREQ_OFFSET, 0);
		rt2x00_set_field16(&word, EEPROM_FREQ_SEQ, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_FREQ, word);
		rt2x00_eeprom_dbg(rt2x00dev, "Freq: 0x%04x\n", word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_OFFSET_BG, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_BG_1, 0);
		rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_BG_2, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_OFFSET_BG, word);
		rt2x00_eeprom_dbg(rt2x00dev, "RSSI OFFSET BG: 0x%04x\n", word);
	} else {
		value = rt2x00_get_field16(word, EEPROM_RSSI_OFFSET_BG_1);
		if (value < -10 || value > 10)
			rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_BG_1, 0);
		value = rt2x00_get_field16(word, EEPROM_RSSI_OFFSET_BG_2);
		if (value < -10 || value > 10)
			rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_BG_2, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_OFFSET_BG, word);
	}

	rt2x00_eeprom_read(rt2x00dev, EEPROM_RSSI_OFFSET_A, &word);
	if (word == 0xffff) {
		rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_A_1, 0);
		rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_A_2, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_OFFSET_A, word);
		rt2x00_eeprom_dbg(rt2x00dev, "RSSI OFFSET A: 0x%04x\n", word);
	} else {
		value = rt2x00_get_field16(word, EEPROM_RSSI_OFFSET_A_1);
		if (value < -10 || value > 10)
			rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_A_1, 0);
		value = rt2x00_get_field16(word, EEPROM_RSSI_OFFSET_A_2);
		if (value < -10 || value > 10)
			rt2x00_set_field16(&word, EEPROM_RSSI_OFFSET_A_2, 0);
		rt2x00_eeprom_write(rt2x00dev, EEPROM_RSSI_OFFSET_A, word);
	}


	printk(KERN_INFO "UT: EEPROM validated. \n");
	return 0;
}


static int rt73usb_init_eeprom(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;
	u16 eeprom;
	u16 rt, rf, rev;

	// this is not rt2x00usb_eeprom_read !
	rt2x00_eeprom_read(rt2x00dev, EEPROM_ANTENNA, &eeprom); 
	
	// Identify RF chipset.
	printk(KERN_INFO "UT: identifying RF chipset... \n");
	rt = rt2x00_get_field32(reg, MAC_CSR0_CHIPSET);
	rf = rt2x00_get_field16(eeprom, EEPROM_ANTENNA_RF_TYPE);
	rev = rt2x00_get_field32(reg, MAC_CSR0_REVISION);
	printk(KERN_INFO "UT: Chipset: rt: 0x%04x, rf: 0x%04x, rev: 0x%04x.", rt, rf, rev);
//	rt2x00_set_chip(rt2x00dev, rt, rf, rev);
	rt2x00dev->chip.rt = rt;
	rt2x00dev->chip.rf = rf;  // correspond to RF2528
	rt2x00dev->chip.rev = rev;

/* disable the following check temporarily for testing purposes
	if (!rt2x00_rt(rt2x00dev, RT2573) || (rt2x00_rev(rt2x00dev) == 0)) {
		printk(KERN_WARNING "UT: Invalid RT chipset detected! \n");
		return -ENODEV;
	}
*/

	// Identify default antenna configuration.	
	printk(KERN_INFO "UT: identifying antenna configuration... \n");
	rt2x00dev->default_ant.tx =
	    rt2x00_get_field16(eeprom, EEPROM_ANTENNA_TX_DEFAULT);
	printk(KERN_INFO "UT: TX antenna configuration: %d \n", rt2x00dev->default_ant.tx);
	rt2x00dev->default_ant.rx =
	    rt2x00_get_field16(eeprom, EEPROM_ANTENNA_RX_DEFAULT);
	printk(KERN_INFO "UT: RX antenna configuration: %d \n", rt2x00dev->default_ant.rx);

	// Read the Frame type.
	printk(KERN_INFO "UT: reading frame type... \n");
	if (rt2x00_get_field16(eeprom, EEPROM_ANTENNA_FRAME_TYPE)) {
		printk(KERN_INFO "UT: frame type capable. \n");
		__set_bit(CAPABILITY_FRAME_TYPE, &rt2x00dev->cap_flags);
	}

	// Detect if this device has an hardware controlled radio.
	printk(KERN_INFO "UT: detecting hw controlled radio... \n");
	if (rt2x00_get_field16(eeprom, EEPROM_ANTENNA_HARDWARE_RADIO)) {
		printk(KERN_INFO "UT: HW controlled radio capable. \n");	
		__set_bit(CAPABILITY_HW_BUTTON, &rt2x00dev->cap_flags);
	}

	// * Read frequency offset.
	printk(KERN_INFO "UT: reading freq offset... ");
	rt2x00_eeprom_read(rt2x00dev, EEPROM_FREQ, &eeprom);
	rt2x00dev->freq_offset = rt2x00_get_field16(eeprom, EEPROM_FREQ_OFFSET);
	printk(KERN_INFO "UT: frequency offet =  0x%x.\n", rt2x00dev->freq_offset);
	
	//Read external LNA informations.
	printk(KERN_INFO "UT: reading external LNA info... \n");
	rt2x00_eeprom_read(rt2x00dev, EEPROM_NIC, &eeprom);

	if (rt2x00_get_field16(eeprom, EEPROM_NIC_EXTERNAL_LNA)) {
		printk(KERN_INFO "UT: external LNA ABG capable. \n");	
		__set_bit(CAPABILITY_EXTERNAL_LNA_A, &rt2x00dev->cap_flags);
		__set_bit(CAPABILITY_EXTERNAL_LNA_BG, &rt2x00dev->cap_flags);
	}

	printk(KERN_INFO "UT: Capability flag: 0x%08lx \n", rt2x00dev->cap_flags);
	
	// Omitted: LED configuration
	printk(KERN_INFO "UT: skipped: LED configuration. \n");

	return 0;	

}


// RF value list for RF2528, Supports: 2.4 GHz
static const struct rf_channel rf_vals_bg_2528[] = {
	{ 1,  0x00002c0c, 0x00000786, 0x00068255, 0x000fea0b },
	{ 2,  0x00002c0c, 0x00000786, 0x00068255, 0x000fea1f },
	{ 3,  0x00002c0c, 0x0000078a, 0x00068255, 0x000fea0b },
	{ 4,  0x00002c0c, 0x0000078a, 0x00068255, 0x000fea1f },
	{ 5,  0x00002c0c, 0x0000078e, 0x00068255, 0x000fea0b },
	{ 6,  0x00002c0c, 0x0000078e, 0x00068255, 0x000fea1f },
	{ 7,  0x00002c0c, 0x00000792, 0x00068255, 0x000fea0b },
	{ 8,  0x00002c0c, 0x00000792, 0x00068255, 0x000fea1f },
	{ 9,  0x00002c0c, 0x00000796, 0x00068255, 0x000fea0b },
	{ 10, 0x00002c0c, 0x00000796, 0x00068255, 0x000fea1f },
	{ 11, 0x00002c0c, 0x0000079a, 0x00068255, 0x000fea0b },
	{ 12, 0x00002c0c, 0x0000079a, 0x00068255, 0x000fea1f },
	{ 13, 0x00002c0c, 0x0000079e, 0x00068255, 0x000fea0b },
	{ 14, 0x00002c0c, 0x000007a2, 0x00068255, 0x000fea13 },
};

static int rt73usb_probe_hw_mode(struct rt2x00_dev *rt2x00dev)
{
	struct hw_mode_spec *spec = &rt2x00dev->spec;
	struct channel_info *info;
	char *tx_power;
	unsigned int i;

	/*
	 * Initialize all hw fields.
	 *
	 * Don't set IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING unless we are
	 * capable of sending the buffered frames out after the DTIM
	 * transmission using rt2x00lib_beacondone. This will send out
	 * multicast and broadcast traffic immediately instead of buffering it
	 * infinitly and thus dropping it after some time.
	 */
	rt2x00dev->hw->flags =
	    IEEE80211_HW_SIGNAL_DBM |
	    IEEE80211_HW_SUPPORTS_PS |
	    IEEE80211_HW_PS_NULLFUNC_STACK;

	SET_IEEE80211_DEV(rt2x00dev->hw, rt2x00dev->dev);
	SET_IEEE80211_PERM_ADDR(rt2x00dev->hw,
				rt2x00_eeprom_addr(rt2x00dev,
						   EEPROM_MAC_ADDR_0));

	//Initialize hw_mode information.
	spec->supported_bands = SUPPORT_BAND_2GHZ;
	spec->supported_rates = SUPPORT_RATE_CCK | SUPPORT_RATE_OFDM;

	// for RF2528
	spec->num_channels = ARRAY_SIZE(rf_vals_bg_2528);
	spec->channels = rf_vals_bg_2528;
	printk(KERN_INFO "UT: number of channels: %d \n", spec->num_channels);	

	// Create channel information array
	info = kcalloc(spec->num_channels, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	spec->channels_info = info;

	tx_power = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_G_START);
	for (i = 0; i < 14; i++) {
		info[i].max_power = MAX_TXPOWER;
		info[i].default_power1 = TXPOWER_FROM_DEV(tx_power[i]);
	}

	if (spec->num_channels > 14) {
		tx_power = rt2x00_eeprom_addr(rt2x00dev, EEPROM_TXPOWER_A_START);
		for (i = 14; i < spec->num_channels; i++) {
			info[i].max_power = MAX_TXPOWER;
			info[i].default_power1 =
					TXPOWER_FROM_DEV(tx_power[i - 14]);
		}
	}
	
	return 0;
}


static int rt73usb_probe_hw(struct rt2x00_dev *rt2x00dev)
{	
	int retval; 

	retval = rt73usb_validate_eeprom(rt2x00dev);
	if (retval)
		return retval;
	
	retval = rt73usb_init_eeprom(rt2x00dev);
	if (retval){
		printk(KERN_WARNING "UT: EEPROM init failed.");	
		return retval;
	}


	// need to insert code to enable rfkill polling

	retval = rt73usb_probe_hw_mode(rt2x00dev); 
	if (retval){
		printk(KERN_WARNING "UT: HW probe failed.");	
		return retval;
	}
	

	__set_bit(CAPABILITY_CONTROL_FILTERS, &rt2x00dev->cap_flags);
	__set_bit(REQUIRE_FIRMWARE, &rt2x00dev->cap_flags);
	//__set_bit(CAPABILITY_HW_CRYPTO, &rt2x00dev->cap_flags);
	__set_bit(CAPABILITY_LINK_TUNING, &rt2x00dev->cap_flags);
	__set_bit(REQUIRE_PS_AUTOWAKE, &rt2x00dev->cap_flags);

	// Set the rssi offset
	rt2x00dev->rssi_offset = DEFAULT_RSSI_OFFSET;

	print_hw_info(rt2x00dev->hw);
	printk(KERN_INFO "UT: HW probe finished. \n");		

	return 0;
}

/***************** UT: mac80211 operations *******************/
/* the functions should migrate to usb_test_mac.c little by little */
static void ut_mac_tx (struct ieee80211_hw *hw, 
			struct ieee80211_tx_control *control,
			struct sk_buff *skb)
{  
};

static void ut_mac_stop (struct ieee80211_hw *hw)
{  
};
static int ut_mac_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{  
	return 0;
};
static void ut_mac_remove_interface (struct ieee80211_hw *hw,
					struct ieee80211_vif *vif)
{  
};
static int ut_mac_config (struct ieee80211_hw *hw, u32 changed)
{  
	return 0;
};
static void ut_mac_configure_filter (struct ieee80211_hw *hw,
					unsigned int changed_flags,
					unsigned int *total_flags,u64 multicast)
{  
};
static int ut_mac_set_tim (struct ieee80211_hw *hw, struct ieee80211_sta *sta,bool set)
{  
	return 0;
};
static int ut_mac_set_key (struct ieee80211_hw *hw, enum set_key_cmd cmd,
			struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			struct ieee80211_key_conf *key)
{  
	return 0;
};
static void ut_mac_sw_scan_start (struct ieee80211_hw *hw)
{  
};
static void ut_mac_sw_scan_complete (struct ieee80211_hw *hw)
{  
};
static int ut_mac_get_stats (struct ieee80211_hw *hw,
				struct ieee80211_low_level_stats *stats)
{
	return 0;  
};
static void ut_mac_bss_info_changed (struct ieee80211_hw *hw,
					struct ieee80211_vif *vif,
					struct ieee80211_bss_conf *info,u32 changed)
{  
};
static int ut_mac_conf_tx (struct ieee80211_hw *hw,
			struct ieee80211_vif *vif, u16 ac,
			const struct ieee80211_tx_queue_params *params)
{  
	return 0;
};
static u64 ut_mac_get_tsf (struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{  	
	return 0;
};
static void ut_mac_rfkill_poll (struct ieee80211_hw *hw)
{  
};
static void ut_mac_flush (struct ieee80211_hw *hw, u32 queues, bool drop)
{  
};
static int ut_mac_set_antenna (struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant)
{  
	return 0;
};
static int ut_mac_get_antenna (struct ieee80211_hw *hw, u32 *tx_ant, u32 *rx_ant)
{  
	return 0;
};
static int ut_mac_get_ringparam (struct ieee80211_hw *hw,
				u32 *tx, u32 *tx_max, u32 *rx, u32 *rx_max)
{  
	return 0;
};
static bool ut_mac_tx_frames_pending (struct ieee80211_hw *hw)
{  
	return true;
};


static const struct ieee80211_ops ut_mac80211_ops = {
	.tx			= ut_mac_tx,
	.start			= ut_mac_start,
	.stop			= ut_mac_stop,
	.add_interface		= ut_mac_add_interface,
	.remove_interface	= ut_mac_remove_interface,
	.config			= ut_mac_config,
	.configure_filter	= ut_mac_configure_filter,
	.set_tim		= ut_mac_set_tim,
	.set_key		= ut_mac_set_key,
	.sw_scan_start		= ut_mac_sw_scan_start,
	.sw_scan_complete	= ut_mac_sw_scan_complete,
	.get_stats		= ut_mac_get_stats,
	.bss_info_changed	= ut_mac_bss_info_changed,
	.conf_tx		= ut_mac_conf_tx,
	.get_tsf		= ut_mac_get_tsf,
	.rfkill_poll		= ut_mac_rfkill_poll,
	.flush			= ut_mac_flush,
	.set_antenna		= ut_mac_set_antenna,
	.get_antenna		= ut_mac_get_antenna,
	.get_ringparam		= ut_mac_get_ringparam,
	.tx_frames_pending	= ut_mac_tx_frames_pending,
};

static const struct rt2x00lib_ops rt73usb_rt2x00_ops = {
	.probe_hw		= rt73usb_probe_hw,
	.get_firmware_name = rt73usb_get_firmware_name,
	.check_firmware = rt73usb_check_firmware,
	.load_firmware = rt73usb_load_firmware,
	.initialize		= ut_initialize,
/*	.uninitialize		= rt2x00usb_uninitialize,
	.clear_entry		= rt2x00usb_clear_entry,
	.set_device_state	= rt73usb_set_device_state,
	.rfkill_poll		= rt73usb_rfkill_poll,
	.link_stats		= rt73usb_link_stats,
	.reset_tuner		= rt73usb_reset_tuner,
	.link_tuner		= rt73usb_link_tuner,
	.watchdog		= rt2x00usb_watchdog,
	.start_queue		= rt73usb_start_queue,
	.kick_queue		= rt2x00usb_kick_queue,
	.stop_queue		= rt73usb_stop_queue,
	.flush_queue		= rt2x00usb_flush_queue,
	.write_tx_desc		= rt73usb_write_tx_desc,
	.write_beacon		= rt73usb_write_beacon,
	.clear_beacon		= rt73usb_clear_beacon,
	.get_tx_data_len	= rt73usb_get_tx_data_len,
	.fill_rxdone		= rt73usb_fill_rxdone,
	.config_shared_key	= rt73usb_config_shared_key,
	.config_pairwise_key	= rt73usb_config_pairwise_key,
	.config_filter		= rt73usb_config_filter,
	.config_intf		= rt73usb_config_intf,
	.config_erp		= rt73usb_config_erp,
	.config_ant		= rt73usb_config_ant,
	.config			= rt73usb_config,	
*/	
};

// This is incomplete. Need more initializations here
static const struct rt2x00_ops ut_ops = {
	.name = KBUILD_MODNAME,	
	.max_ap_intf		= 4,
	.eeprom_size		= EEPROM_SIZE,
	.rf_size		= RF_SIZE,
	.tx_queues		= NUM_TX_QUEUES,
	.lib			= &rt73usb_rt2x00_ops,  
	.mac80211_ops 		= &ut_mac80211_ops,
}; 




/* This is the probe function that also initializes wifi device */
static int usb_test_probe(struct usb_interface *usb_intf,
		      const struct usb_device_id *id)
{
	
	struct usb_device *usb_dev;
	int status = 0;
	struct ieee80211_hw *hw;
	struct rt2x00_dev *rt2x00dev;	

	status = skel_probe(usb_intf, id);
	if (status) {
		printk(KERN_WARNING "UT: unable to probe.\n");
		goto error;
	}
	
	usb_dev = interface_to_usbdev(usb_intf);
	usb_dev = usb_get_dev(usb_dev);
	usb_reset_device(usb_dev);
	
	hw = ieee80211_alloc_hw(sizeof(struct rt2x00_dev), (&ut_ops)->mac80211_ops);	
	if(!hw) {
		printk(KERN_WARNING "UT: error in alloc 80211 hw. \n");
		goto error;
	} else {
		printk(KERN_INFO "UT: Priv size is %lu", sizeof(struct rt2x00_dev));
		printk(KERN_INFO "UT: 80211 hw allocated. \n");
		print_hw_info(hw);
	}
	
	usb_set_intfdata(usb_intf, hw);  
	
	rt2x00dev = hw->priv;
	rt2x00dev->dev = &usb_intf->dev;
	rt2x00dev->ops = &ut_ops; // rt73usb_ops
	rt2x00dev->hw = hw;

	rt2x00_set_chip_intf(rt2x00dev, RT2X00_CHIP_INTF_USB);
	
	/*
	 * TODO: need some inits here for rx/tx WORK 
	 */

	/* ref: rt2x00usb_alloc_reg */
	rt2x00dev->csr.cache = kzalloc(CSR_CACHE_SIZE, GFP_KERNEL);
	printk(KERN_INFO "UT: CSR cache size allocated: %u \n", CSR_CACHE_SIZE);	
	
	rt2x00dev->eeprom = kzalloc(rt2x00dev->ops->eeprom_size, GFP_KERNEL);
	printk(KERN_INFO "UT: EEPROM size allocated: %u \n", rt2x00dev->ops->eeprom_size);
	
	rt2x00dev->rf = kzalloc(rt2x00dev->ops->rf_size, GFP_KERNEL);
	printk(KERN_INFO "UT: RF size allocated: %u \n", rt2x00dev->ops->rf_size);
	
		
	/*ref: rt2x00lib_probe_dev */
	status = rt2x00lib_probe_dev(rt2x00dev);
	if (status)
		goto error;
	
	printk(KERN_INFO "UT: UT probing finished. \n");
	
	return 0;

error:
	return status;

}

static void usb_test_disconnect(struct usb_interface *usb_intf)
{
	struct usb_skel *dev;
	
	struct ieee80211_hw *hw = usb_get_intfdata(usb_intf);
//	struct rt2x00_dev *rt2x00dev = hw->priv; 
	
//	int minor = usb_intf->minor;
	
	printk(KERN_INFO "UT: disconnecting... \n");	
	printk(KERN_INFO "UT: freeing ieee80211 hw... \n");	
	ieee80211_free_hw(hw);
	printk(KERN_INFO "UT: ieee80211 hw freed. \n");		

	printk(KERN_INFO "UT: nulling USB interface data... \n");	
	dev = usb_get_intfdata(usb_intf);
	usb_set_intfdata(usb_intf, NULL);
	printk(KERN_INFO "UT: USB interface nulled. \n");	

	printk(KERN_INFO "UT: releasing the device... \n");	
	usb_put_dev(interface_to_usbdev(usb_intf));
	printk(KERN_INFO "UT: device released. \n");		

	/* give back our minor */
	printk(KERN_INFO "UT: deregistering USB device... \n");	
	usb_deregister_dev(usb_intf, &skel_class);
	printk(KERN_INFO "UT: USB device deregistered. \n");	

	printk(KERN_INFO "UT: Skipped:  killing anchored urbs.\n");	
	printk(KERN_INFO "UT: Skipped:  decreasing usage count.\n");
	printk(KERN_INFO "UT: Now disconnected. \n");

}

static void skel_draw_down(struct usb_skel *dev)
{
	int time;

	time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
	if (!time)
		usb_kill_anchored_urbs(&dev->submitted);
	usb_kill_urb(dev->bulk_in_urb);
}


static struct usb_driver skel_driver = {
	.name =		"usb_test",
	.probe =	usb_test_probe,
	.disconnect =	usb_test_disconnect,
//	.suspend =	skel_suspend, 
//	.resume =	skel_resume,  
//	.pre_reset =	skel_pre_reset, 
//	.post_reset =	skel_post_reset,
	.id_table =	skel_table,
//	.supports_autosuspend = 1,
};

module_usb_driver(skel_driver);

MODULE_LICENSE("GPL");
