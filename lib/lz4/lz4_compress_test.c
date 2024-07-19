// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LZ4 compressor tester
 *
 * Author: Lasse Collin <lasse.collin@tukaani.org>
 * Author: Gabriel de Perthuis <g2p.code@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/lz4.h>

/* Device name to pass to register_chrdev(). */
#define DEVICE_NAME "lz4_compress_test"

/* Dynamically allocated device major number */
static int device_major;

static int lz4_compress_test_open(struct inode *i, struct file *f)
{
	pr_info(DEVICE_NAME ": opened\n");
	return 0;
}

static int lz4_compress_test_release(struct inode *i, struct file *f)
{
	pr_info(DEVICE_NAME ": closed\n");
	return 0;
}

/*
 * Compress the data given to us from userspace.
 */
static ssize_t lz4_compress_test_write(struct file *file, const char __user *buf,
				 size_t size, loff_t *pos)
{
	if (size <= 0)
		return 0;

	void *in = kvmalloc(size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	if (copy_from_user(in, buf, size))
			return -EFAULT;

	// cbuf_len may be smaller than size, this matches bcachefs usage
	// with encoded_extent_max
	size_t cbuf_capacity = min(size, 65536);
	void *cbuf = kvmalloc(cbuf_capacity, GFP_KERNEL);
	if (!cbuf)
		return -ENOMEM;

	void *workspace = kvmalloc(LZ4_MEM_COMPRESS, GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;

	pr_info(DEVICE_NAME ": encoding %zu bytes of input, out capacity %zu\n", size, cbuf_capacity);

	// cast to signed: LZ4_compress_destSize will compare against LZ4_MAX_INPUT_SIZE
	// to ensure this is nonnegative
	int in_len = size;
	int cbuf_len = LZ4_compress_destSize(in, cbuf, &in_len, cbuf_capacity, workspace);
	pr_info(DEVICE_NAME ": compressed %d bytes into %d bytes\n", in_len, cbuf_len);
	BUG_ON(cbuf_len < 0);
	BUG_ON(cbuf_len > cbuf_capacity);

	if (cbuf_len) {
		// Test that what was compressed round-trips correctly
		// Note: we don't assume in_len == size; in case of
		// partial compression we check that the compressed bits do round-trip

		// in_len can be zero; there's a case where zero bytes are compressed into one
		BUG_ON(in_len < 0);
		BUG_ON((size_t)in_len > size);
		void *compare = kvmalloc(max(in_len, 1), GFP_KERNEL);
		if (!compare)
			return -ENOMEM;
		int ret = LZ4_decompress_safe(cbuf, compare, cbuf_len, in_len);
		BUG_ON(ret != in_len);
		BUG_ON(bcmp(in, compare, in_len) != 0);
	}

	if (cbuf_len && in_len)
		return in_len;
	return -EIO;
}

/* Register the character device. */
static int __init lz4_compress_test_init(void)
{
	static const struct file_operations fileops = {
		.owner = THIS_MODULE,
		.open = &lz4_compress_test_open,
		.release = &lz4_compress_test_release,
		.write = &lz4_compress_test_write
	};

	device_major = register_chrdev(0, DEVICE_NAME, &fileops);
	if (device_major < 0) {
		return device_major;
	}

	pr_info(DEVICE_NAME ": module loaded\n");
	pr_info(DEVICE_NAME ": Create a device node with 'mknod "
			 DEVICE_NAME " c %d 0' and write data to it.\n",
			device_major);
	return 0;
}

static void __exit lz4_compress_test_exit(void)
{
	unregister_chrdev(device_major, DEVICE_NAME);
	pr_info(DEVICE_NAME ": module unloaded\n");
}

module_init(lz4_compress_test_init);
module_exit(lz4_compress_test_exit);

MODULE_DESCRIPTION("LZ4 compressor tester");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Gabriel de Perthuis <g2p.code@gmail.com>");

MODULE_LICENSE("GPL");
