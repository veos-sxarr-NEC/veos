/**
 * Copyright (C) 2018 by NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file sys_veaio.c
 * @brief Handle AIO system call on VE
 *
 * @internal
 * @author VEAIO
 */

#include <dhash.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "sys_veaio.h"
#include "handle.h"
#include "sys_common.h"
#include "mm_transfer.h"
#include <semaphore.h>
#include <libvepseudo.h>

#define VH_AIO_HASH_SIZE 512
#define VE_AIO_OP_READ   0
#define VE_AIO_OP_WRITE  1
#define VE_AIO_MAXSIZE   (2*1024*1024*1024UL - 4*1024)
#define VE_AIO_MAXWORKER 256

#define MIN(A,B) ({ \
    typeof(A) A_ = (A); \
    typeof(B) B_ = (B); \
    A_ < B_ ? A_ : B_;  \
})

#define MAX(A,B) ({ \
    typeof(A) A_ = (A); \
    typeof(B) B_ = (B); \
    A_ > B_ ? A_ : B_;  \
})

/* A lock for vh_aio_hash and vh_aio_ctx->refcnt  */
pthread_mutex_t vh_aio_hash_lock;
/* A hash table for vh_aio_ctx */
hash_table_t *vh_aio_hash;
/* A attribute for pthread_create() */
pthread_attr_t thread_attr;

static int ve_aio_worker_bufsize = (8*1024*1024);
static int ve_aio_worker_num = 4;
static int ve_aio_worker_isatomic = 0;
static int ve_aio_worker_cnt = 0;

typedef struct seq {
    int32_t             index;
    struct vh_aio_ctx   *ctx;
    struct seq          *next;
    int64_t             chksz;
    int64_t             shift;
    sem_t               fence;
} seq_t;

static seq_t dummy = { 0 };
static seq_t *seqs_head = NULL;
static seq_t *seqs_tail = NULL;

static int ve_aio_worker_term = 0;
static pthread_cond_t ve_aio_worker_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t ve_aio_worker_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Initialize hash table and thread attribute */
__attribute__((constructor))
static void ve_aio_constructor(void)
{
	int ret;
	ret = hash_create(VH_AIO_HASH_SIZE, &vh_aio_hash, NULL, NULL);
	if (HASH_SUCCESS != ret) {
		PSEUDO_ERROR("VEAIO: Fail to initialize hash table (%s)",
				hash_error_string(ret));
		fprintf(stderr, "VEAIO: Fail to initialize hash table\n");
		pseudo_abort();
	}

	ret = pthread_attr_init(&thread_attr);
	if (0 != ret) {
		PSEUDO_ERROR("VEAIO: Fail to initialize thread attribute");
		fprintf(stderr, "VEAIO: Fail to initialize thread attribute\n");
		errno = ret;
		pseudo_abort();
	}

	ret = pthread_attr_setdetachstate(&thread_attr,
			PTHREAD_CREATE_DETACHED);
	if (0 != ret) {
                PSEUDO_ERROR("VEAIO: Fail to set thread attribute");
		fprintf(stderr, "VEAIO: Fail to set thread attribute\n");
                errno = ret;
                pseudo_abort();
        }

	seqs_head = &dummy;
	seqs_tail = seqs_head;

	const char *env;

	if ((env = getenv("VE_ASYNC_IO_BUFFER")) != NULL)
		ve_aio_worker_bufsize=MAX(1, MIN(VE_AIO_MAXSIZE, (uint64_t)strtoll(env, NULL, 0)));
	if ((env = getenv("VE_ASYNC_IO_THREAD")) != NULL)
		ve_aio_worker_num=MIN(8, strtol(env, NULL, 0));
	if ((env = getenv("VE_ATOMIC_IO")) != NULL)
		ve_aio_worker_isatomic = strtol(env, NULL, 0);
	if ((env = getenv("VE_ASYNC_IO_ATOMIC")) != NULL)
		ve_aio_worker_isatomic = strtol(env, NULL, 0);

}

/**
 * @brief release resource of vh_aio_context
 *
 * @param[in] vh_ctx vh_aio_context to be released
 *
 * @return this function always return 0
 */
static int
free_vh_aio_ctx(struct vh_aio_ctx *vh_ctx)
{
	if (0 != pthread_cond_destroy(&vh_ctx->cond)) {
		PSEUDO_ERROR("VEAIO: failure destroy condtion valiable in vh_ctx:%lx",
				(long unsigned int)vh_ctx);
	}
	if (0 != pthread_mutex_destroy(&vh_ctx->vh_aio_status_lock)) {
		PSEUDO_ERROR("VEAIO: failure destroy mutex:vh_aio_status_lock in vh_ctx:%lx",
				(long unsigned int)vh_ctx);
	}
	free(vh_ctx);
	return 0;
}

/**
 * @brief delete vh_aio_hash entry specified by argument
 *
 * @param[in] vh_ctx vh_aio_context to be deleted from hash
 *
 * @return 0 on success, 1 on not delete, otherwise on failure
 */
static int
vh_aio_hash_delete(struct vh_aio_ctx *vh_ctx)
{
	int ret = -1;
	hash_key_t key;
        hash_value_t value;

	PSEUDO_DEBUG("VEAIO: enter vh_aio_hash_delete");

        key.type = HASH_KEY_ULONG;
        key.ul = (unsigned long)vh_ctx->ve_ctx;
        pthread_mutex_lock(&vh_aio_hash_lock);
        vh_ctx->refcnt--;
        if (0 == vh_ctx->refcnt) {
		PSEUDO_DEBUG("VEAIO: delete entry{vh_ctx:%lx, ve_ctx:%lx} from vh_aio_hash",
				(long unsigned int)vh_ctx,
				(long unsigned int)vh_ctx->ve_ctx);

                /* Look up and delete entry in hash */
                ret = hash_lookup(vh_aio_hash, &key, &value);
                switch (ret) {
                case HASH_SUCCESS:
                        if(vh_ctx == (struct vh_aio_ctx *)value.ptr)
                                hash_delete(vh_aio_hash, &key);
			ret = 0;
                        break;
                case HASH_ERROR_BAD_KEY_TYPE:
                case HASH_ERROR_KEY_NOT_FOUND:
                default:
			PSEUDO_ERROR("VEAIO: cannot lookup vh_ctx in hash table \"%lx\" (%s)",
					key.ul, hash_error_string(ret));
                        break;
                }
        } else {
		ret = 1;
	}
        pthread_mutex_unlock(&vh_aio_hash_lock);
	return ret;
}

/**
 * @brief worker thread for AIO read/write request
 *
 * @param[in] varg Context managing this read request on VH
 */
static void *
_sys_ve_aio2_io(void *varg)
{
	veos_handle *handle;
	char *lbuf = NULL;

	/* create veos handle  */
	handle = veos_handle_copy((veos_handle *)varg);
	if (handle == NULL) {
		PSEUDO_ERROR("VEAIO: Fail to create veos handle");
		fprintf(stderr, "VEAIO: Fail to open socket or device file\n");
		pseudo_abort();
	}

	lbuf = (char *)malloc(ve_aio_worker_bufsize);
	if (NULL == lbuf) {
		PSEUDO_ERROR("VEAIO: Fail to allocate aio buffer");
		fprintf(stderr, "VEAIO: Fail to allocate aio buffer\n");
		pseudo_abort();
	}

	while (1) {
		seq_t *seq;

		pthread_mutex_lock(&ve_aio_worker_mutex);

		for (;;) {
			seq = seqs_head->next;
			if (seq || ve_aio_worker_term)
				break;
			pthread_cond_wait(&ve_aio_worker_cond,
					  &ve_aio_worker_mutex);
		}

		if (ve_aio_worker_term) {
			pthread_mutex_unlock(&ve_aio_worker_mutex);
			break;
		}

		seqs_head->next = seq->next;
		if (seqs_head->next == NULL)
			seqs_tail = seqs_head;

		if (seqs_head->next)
			pthread_cond_signal(&ve_aio_worker_cond);

		pthread_mutex_unlock(&ve_aio_worker_mutex);

		struct vh_aio_ctx     *ctx = seq->ctx;
		struct ve_aio2_result *res = &ctx->res[seq->index];

		int32_t *leave  = &ctx->leave;
		sem_t *fence_self, *fence_next;
        	fence_self = &seq->fence;
        	if (seq->index == ctx->total - 1) {
			/* This is the last IO of request and
			 * No need to post semaphore to next seq*/
            		fence_next = fence_self;
        	} else {
            		fence_next = &seq->next->fence;
        	}

        	int32_t op      = ctx->op;
        	int32_t fd      = ctx->fd;
		pid_t   tid     = ctx->tid;
        	uint64_t buf    = ctx->buf + seq->shift;
        	int64_t count   = seq->chksz;
        	int64_t offset  = ctx->offset + seq->shift;

       		ssize_t retval  = 0;
        	int errval  = 0;

		void *p;
		if (ve_aio_worker_isatomic && count > ve_aio_worker_bufsize) {
			p = malloc(count);
			if (!p) {
				errval = errno;
				*leave = 1;
			}
		} else {
			p = lbuf;
		}

		switch(op) {
		case VE_AIO_OP_READ:
			if (*leave != 1) {
				retval = pread(fd, p, count, offset);
				if (retval == -1) {
					errval = errno;
					*leave = 1;
				} else if (retval != count) {
					count  = retval;
					*leave = 1;
				}
			}

			sem_wait(fence_self);

			if (*leave != 1 && count > 0) {
				int ret = 0;
				ret = ve_send_data_tid(handle, buf, count, p, tid);
				if (ret < 0) {
					errval = -ret;
					*leave = 1;
				}

			}
			break;

		case VE_AIO_OP_WRITE:
			if (*leave != 1 && count > 0) {
				int ret = 0;
				ret = ve_recv_data_tid(handle, buf, count, p, tid);
				if (ret < 0) {
					errval = -ret;
					*leave = 1;
				}
			}

			sem_wait(fence_self);

			if (*leave != 1 && count > 0) {
				retval = pwrite(fd, p, count, offset);
				if (retval == -1) {
					errval = errno;
					*leave = 1;
				} else if (retval != count) {
					count = retval;
					*leave = 1;
				}
			}
			break;
		}

		sem_post(fence_next);

		if (p && p != lbuf)
			free(p);

		sem_destroy(fence_self);

		res->errnoval = errval;
		res->retval = retval;

		if (__sync_fetch_and_sub(&ctx->alive, 1) == 1) {
			retval = 0;
			errval = 0;
			
			struct ve_aio2_result *arr_res = ctx->res;
			int i;
			for (i = 0; i < ctx->total; i++) {
				if (arr_res[i].errnoval != 0) {
					errval = arr_res[i].errnoval;
					break;
				}
				retval += arr_res[i].retval;
			}

			struct ve_aio2_result merge;
			merge.active = 0;

			if (errval == 0 || retval > 0) {
				merge.retval = retval;
				merge.errnoval = 0;
			} else {
				merge.retval = -1;
				merge.errnoval = errval;
			}

			if (ve_send_data_tid(handle, (uint64_t)(ctx->ve_ctx)
						+ offsetof(struct ve_aio2_ctx, result.binary),
						sizeof(merge.binary), &merge.binary, tid) < 0) {
				perror("ve_send_data_tid");
				pseudo_abort();
			}

			/* Wake up thread slept by sys_ve_aio_wait() */
			pthread_mutex_lock(&ctx->vh_aio_status_lock);
			ctx->status = VE_AIO_COMPLETE;
			pthread_cond_broadcast(&ctx->cond);
			pthread_mutex_unlock(&ctx->vh_aio_status_lock);

			/* Resource release  */
			if (0 == vh_aio_hash_delete(ctx))
				free_vh_aio_ctx(ctx);

		}
	}

        /* Resource release  */
	veos_handle_free(handle);
	free(lbuf);
	pthread_mutex_lock(&ve_aio_worker_mutex);
	ve_aio_worker_cnt--;
	pthread_cond_broadcast(&ve_aio_worker_cond);
	pthread_mutex_unlock(&ve_aio_worker_mutex);

	return NULL;
}

int sys_ve_aio2_init(veos_handle *handle)
{
        int ret = 0;
        int i;
	pthread_t thread;

	if (ve_aio_worker_cnt)
		return -EAGAIN;

        for (i = 0; i < ve_aio_worker_num; i++) {
		ret = pthread_create(&thread, &thread_attr,
				_sys_ve_aio2_io, (void *)handle);
                if (ret) {
                        ret = -ret;

			pthread_mutex_lock(&ve_aio_worker_mutex);
			ve_aio_worker_term = 1;
			pthread_cond_broadcast(&ve_aio_worker_cond);
			pthread_mutex_unlock(&ve_aio_worker_mutex);
			
			pthread_mutex_lock(&ve_aio_worker_mutex);
			while(ve_aio_worker_cnt)
				pthread_cond_wait(&ve_aio_worker_cond, &ve_aio_worker_mutex);
			pthread_mutex_unlock(&ve_aio_worker_mutex);

			ve_aio_worker_term = 0;
                        break;
                } else {
			pthread_mutex_lock(&ve_aio_worker_mutex);
			ve_aio_worker_cnt++;
			pthread_mutex_unlock(&ve_aio_worker_mutex);
		}
        }

        return ret;
}

/**
 * @brief This function is implementation of sys_ve_aio_read()/write()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File discriptor which refer to a file this function reads from
 *               or writes to
 * @param[in] count Number of bytes read/write
 * @param[in] buff Buffer into which this function stores the read/write data
 * @param[in] offset File offset
 * @param[in] op specify which operation, read or write
 *
 * @return Return 0 on success. Negative value on failure.
 */
static int
do_aio2(veos_handle *handle, struct ve_aio2_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset, int op)
{
        int ret;
        struct vh_aio_ctx *vh_ctx;

        hash_key_t key;
        hash_value_t value;

	uint64_t total;
	int64_t blksz;

	if (ve_aio_worker_cnt <= 0) {
		PSEUDO_ERROR("VEAIO: No IO worker thread on VH");
		return -EINVAL;
	}

	if (ve_aio_worker_isatomic) {
		count = MIN(count, VE_AIO_MAXSIZE);
		blksz = MAX(1, count);
	} else {
		blksz = ve_aio_worker_bufsize;
	}

	if (count == 0)
		total = 1;
	else if (count % blksz)
		total = count / blksz + 1;
	else
		total = count / blksz;

        if (INT_MAX+1ULL < total ||  NULL == ve_ctx) {
                return -EINVAL;
        }

        vh_ctx = calloc(1, sizeof(struct vh_aio_ctx) + sizeof(seq_t)*total
			 + sizeof(struct ve_aio2_result)*total);
        if (NULL == vh_ctx) {
                PSEUDO_ERROR("VEAIO: No memory for AIO context on VH");
                return -ENOMEM;
        }
	
	vh_ctx->total = total;
	vh_ctx->alive = total;
	vh_ctx->leave = 0;

	vh_ctx->seq = (seq_t *)(vh_ctx + 1);
	vh_ctx->res = (struct ve_aio2_result *)(vh_ctx->seq + total);

        /* Initialize vh_aio_context */
        ret = pthread_mutex_init(&vh_ctx->vh_aio_status_lock, NULL);
	if (0 != ret) {
		PSEUDO_ERROR("VEAIO: Fail to initialize mutext vh_aio_statu_lock");
		free(vh_ctx);
		return -ENOMEM;
	}
        ret = pthread_cond_init(&vh_ctx->cond, NULL);
	if (0 != ret) {
		PSEUDO_ERROR("VEAIO: Fail to initialize condition variable");
		pthread_mutex_destroy(&vh_ctx->vh_aio_status_lock);
		free(vh_ctx);
		return -ENOMEM;
	}
        /* No need to aquire lock in initialize step */
        vh_ctx->status = VE_AIO_INPROGRESS;
	vh_ctx->tid = syscall(SYS_gettid);
        vh_ctx->ve_ctx = (void *)ve_ctx;
        vh_ctx->fd = fd;
        vh_ctx->buf = (uint64_t)buf;
        vh_ctx->count = count;
        vh_ctx->offset = offset;
	vh_ctx->op = op;

        /* Create hash entry for VH AIO context  */
        key.type = HASH_KEY_ULONG;
        key.ul = (unsigned long)ve_ctx;
        value.type = HASH_VALUE_PTR;
        value.ptr = (void *)vh_ctx;
        /* Add entry to hash table */
        pthread_mutex_lock(&vh_aio_hash_lock);
        /* If hash table already has entry of this key, value is updated */
        ret = hash_enter(vh_aio_hash, &key, &value);
        vh_ctx->refcnt++;
        pthread_mutex_unlock(&vh_aio_hash_lock);
        switch (ret) {
        case HASH_SUCCESS:
                break;
        case HASH_ERROR_BAD_KEY_TYPE:
        case HASH_ERROR_BAD_VALUE_TYPE:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" (%s)", key.ul,
                                hash_error_string(ret));
                ret = -EINVAL;
                goto ctx_free;
        case HASH_ERROR_NO_MEMORY:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" (%s)", key.ul,
                                hash_error_string(ret));
                ret = -ENOMEM;
                goto ctx_free;
        default:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" unexpected (%s)",
                                key.ul, hash_error_string(ret));
                ret = -EAGAIN;
                goto ctx_free;
        }

	seq_t new, *seq;
	seq = &new;

	int32_t index = 0;
	int64_t shift = 0;
	int64_t rests = count;
	do {
		seq->next = &(vh_ctx->seq[index]);
		seq = seq->next;
		seq->next = NULL;
		seq->ctx  = vh_ctx;

		int64_t chksz = MIN(rests, blksz);

		seq->index  = index;
		seq->chksz  = chksz;
		seq->shift  = shift;

		sem_init(&seq->fence, 0, 0);

		index       += 1;
		shift       += chksz;

		rests       -= chksz;

	} while (0 < rests && 0 < (int64_t)count);
	
	sem_post(&new.next->fence);

	pthread_mutex_lock(&ve_aio_worker_mutex);
	seqs_tail->next = new.next;
	seqs_tail       = seq;
	pthread_cond_signal(&ve_aio_worker_cond);
	pthread_mutex_unlock(&ve_aio_worker_mutex);

	return 0;

ctx_free:
        free_vh_aio_ctx(vh_ctx);
        return ret;
}

/**
 * @brief This function is handler of ve_aio_read()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File descriptor which refer to a file this function reads from
 * @param[in] count Number of bytes read
 * @param[in] buff Buffer into which this function stores the read data
 * @param[in] offset File offset
 *
 * @return Return 0 on success. Negative value on failure.
 */
int
sys_ve_aio2_read(veos_handle *handle, struct ve_aio2_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset)
{
        return do_aio2(handle, ve_ctx, fd, count, buf, offset, VE_AIO_OP_READ);
}

/**
 * @brief This function is handler of ve_aio_write()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File discriptor
 * @param[in] count Number of bytes written
 * @param[in] buff Buffer from which this function gets the data to write
 * @param[in] offset File offset
 *
 * @return Return 0 on success. Negative value on failure.
 */
int
sys_ve_aio2_write(veos_handle *handle, struct ve_aio2_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset)
{
	return do_aio2(handle, ve_ctx, fd, count, buf, offset, VE_AIO_OP_WRITE);
}

/**
 * @brief This function is handler of ve_aio_wait()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Address used to search vh_aio_ctx in vh_aio_hash
 *
 * @return Return 0 on success. Negative value on failure.
 */
int
sys_ve_aio2_wait(veos_handle *handle, struct ve_aio2_ctx *ve_ctx)
{
	hash_key_t key;
	hash_value_t value;
	int error; /* For functions of hash table */
	struct vh_aio_ctx *vh_ctx;

	PSEUDO_DEBUG("VEAIO: enter sys_ve_aio_wait");

	if (NULL == ve_ctx)
		return -EINVAL;

	/* Create hash key  */
	key.type = HASH_KEY_ULONG;
	key.ul = (unsigned long)ve_ctx;
	/* Look up hash value in hash table  */
	pthread_mutex_lock(&vh_aio_hash_lock);
	error = hash_lookup(vh_aio_hash, &key, &value);
	switch (error) {
	case HASH_ERROR_KEY_NOT_FOUND:
		PSEUDO_DEBUG("VEAIO: can not lookup context from hash table \"%lx\" (%s)",
				key.ul, hash_error_string(error));
		pthread_mutex_unlock(&vh_aio_hash_lock);
		return 0;
	case HASH_SUCCESS:
		vh_ctx = (struct vh_aio_ctx *)value.ptr;
		vh_ctx->refcnt++;
		pthread_mutex_unlock(&vh_aio_hash_lock);
		PSEUDO_DEBUG("VEAIO: lookup context from hash table \"%lx\" ",
				key.ul);
		break;
	default:
		PSEUDO_ERROR("VEAIO: Unexpected error of hash table, key:\"%lx\" err:(%s)",
				key.ul, hash_error_string(error));
		pthread_mutex_unlock(&vh_aio_hash_lock);
		return -EINVAL;
	}

	/* Check read/write status in worker thread  */
	pthread_mutex_lock(&vh_ctx->vh_aio_status_lock);
	if (VE_AIO_INPROGRESS == vh_ctx->status )
		pthread_cond_wait(&vh_ctx->cond, &vh_ctx->vh_aio_status_lock);
	pthread_mutex_unlock(&vh_ctx->vh_aio_status_lock);
	/* Delete entry from hash table  */
	if (0 == vh_aio_hash_delete(vh_ctx))
		free_vh_aio_ctx(vh_ctx);

	return 0;
}

/* For old API */
/**
 * @brief worker thread for AIO read request
 *
 * @param[in] varg Context managing this read request on VH
 */
static void *
_sys_ve_aio_read(void *varg)
{
        struct vh_aio_ctx *vh_ctx = (struct vh_aio_ctx *)varg;
        veos_handle *handle;
        struct ve_aio_result send = {-1, EIO};
        int status = VE_AIO_COMPLETE;
        char *read_buff = NULL;

        /* create veos handle  */
	handle = veos_handle_copy(vh_ctx->handle);
        /* On failure to create handle, thread can't send reault to VE
         * and pseudo process exit immidietly*/
        if (handle == NULL) {
                PSEUDO_ERROR("VEAIO: Fail to create veos handle");
                fprintf(stderr, "VEAIO: Fail to open socket or device file\n");
                pseudo_abort();
        }

        if (vh_ctx->count > MAX_RW_COUNT)
                vh_ctx->count = MAX_RW_COUNT;

        /* Preparing for pread64() systemcall  */
        if (vh_ctx->buf) {
                read_buff = (char *)malloc(vh_ctx->count*sizeof(char));
                if (NULL == read_buff) {
                        /* pread() doesn't return ENOMEM  */
                        send.errnoval = EIO;
                        send.retval = -1;
                        PSEUDO_ERROR("VEAIO: Fail to create internal memory buffer");
                        goto hndl_return;
                }
        }
        /* Call pread64()  */
        send.retval = pread64(vh_ctx->fd,
                        vh_ctx->buf ? (char *)read_buff : NULL,
                        vh_ctx->count, vh_ctx->offset);
        if(-1 == send.retval) {
                send.errnoval = errno;
                PSEUDO_ERROR("VEAIO: syscall %s failed %s", "SYS_pread64",
                                strerror(errno));
                goto hndl_return;
        } else {
                send.errnoval = 0;
                PSEUDO_DEBUG("VEAIO: pread: retval %zu, buff %p", send.retval,
                                read_buff);
        }

        /* Send read data to VE  */
        if ((0x0 != vh_ctx->buf) && (0 != send.retval)) {
                if (0 > ve_send_data_tid(handle, (uint64_t)vh_ctx->buf,
                                        send.retval, (uint64_t *)read_buff,
                                        vh_ctx->tid)) {
                        send.errnoval = EFAULT;
                        send.retval = -1;
                        PSEUDO_ERROR("VEAIO: Fail to send AIO read buffer to VE memory");
                }
        }
hndl_return:
        /* Send result of pread64()  */
        if (0 > ve_send_data_tid(handle,
			(uint64_t)vh_ctx->ve_ctx
				+ offsetof(struct ve_aio_ctx, result),
                        sizeof(struct ve_aio_result), &send, vh_ctx->tid))
                PSEUDO_ERROR("VEAIO: Fail to send AIO read result to VE memory");
        if (0 > ve_send_data_tid(handle,
			(uint64_t)vh_ctx->ve_ctx
				+ offsetof(struct ve_aio_ctx, status),
                        sizeof(int), &status, vh_ctx->tid)) {
                PSEUDO_ERROR("VEAIO: Fail to send AIO read status to VE memory");
                fprintf(stderr, "VEAIO: Fail to send AIO read status to VE memory\n");
                pseudo_abort();
        }

        /* Wake up thread slept by sys_ve_aio_wait() */
        pthread_mutex_lock(&vh_ctx->vh_aio_status_lock);
        vh_ctx->status = VE_AIO_COMPLETE;
        pthread_cond_broadcast(&vh_ctx->cond);
        pthread_mutex_unlock(&vh_ctx->vh_aio_status_lock);

        /* Resource release  */
        if (0 == vh_aio_hash_delete(vh_ctx))
                free_vh_aio_ctx(vh_ctx);
        free(read_buff);
        veos_handle_free(handle);

        return NULL;
}

/**
 * @brief worker thread for AIO write request
 *
 * @param[in] varg Context managing this read request on VH
 */
static void *
_sys_ve_aio_write(void *varg)
{
        struct vh_aio_ctx *vh_ctx = (struct vh_aio_ctx *)varg;
        veos_handle *handle;
        struct ve_aio_result send = {-1, EIO};
        int status = VE_AIO_COMPLETE;
        char *write_buff = NULL;

        /* create veos handle  */
	handle = veos_handle_copy(vh_ctx->handle);
        /* On failure to create handle, thread can't send reault to VE
         * and pseudo process exit immidietly */
        if (handle == NULL) {
                PSEUDO_ERROR("VEAIO: Fail to create veos handle");
                fprintf(stderr, "VEAIO: Fail to open socket or device file\n");
                pseudo_abort();
        }

        if (vh_ctx->count > MAX_RW_COUNT)
                vh_ctx->count = MAX_RW_COUNT;

        /* Preparing for pwrite64() systemcall  */
        if (vh_ctx->buf) {
                write_buff = (char *)malloc(vh_ctx->count*sizeof(char));
                if (NULL == write_buff) {
                        send.errnoval = EIO;
                        send.retval = -1;
                        PSEUDO_ERROR("VEAIO: Fail to create internal memory buffer");
                        goto hndl_return;
                }

                /* Receive the write buffer */
                if (0 > ve_recv_data_tid(handle, (uint64_t)vh_ctx->buf,
                                vh_ctx->count, (uint64_t *)write_buff,
                                vh_ctx->tid)) {
                        send.errnoval = EFAULT;
                        send.retval = -1;
                        PSEUDO_ERROR("VEAIO: Fail to recieve AIO write buffer from VE memory");
                        goto hndl_return;
                }
        }
        /* Call pwrite64() */
        send.retval = pwrite64(vh_ctx->fd, (char *)write_buff, vh_ctx->count,
                        vh_ctx->offset);
        if(-1 == send.retval) {
                send.errnoval = errno;
                PSEUDO_ERROR("VEAIO: syscall %s failed %s", "SYS_pwrite64",
                                strerror(errno));
        } else {
                send.errnoval = 0;
                PSEUDO_DEBUG("VEAIO: pwrite: retval %zu, buff %p", send.retval,
                                write_buff);
        }
hndl_return:
        /* Send result of pwrite64()  */
        if (0 > ve_send_data_tid(handle,
			(uint64_t)vh_ctx->ve_ctx
                                + offsetof(struct ve_aio_ctx, result),
                        sizeof(struct ve_aio_result), &send, vh_ctx->tid))
                PSEUDO_ERROR("VEAIO: Fail to send AIO write result to VE memory");
        if (0 > ve_send_data_tid(handle,
			(uint64_t)vh_ctx->ve_ctx
				+ offsetof(struct ve_aio_ctx, status),
                        sizeof(int), &status, vh_ctx->tid)) {
                PSEUDO_ERROR("VEAIO: Fail to send AIO write status to VE memory");
                fprintf(stderr, "VEAIO: Fail to send AIO write status to VE memory\n");
                pseudo_abort();
        }

        /* Wake up thread slept by sys_ve_aio_wait() */
        pthread_mutex_lock(&vh_ctx->vh_aio_status_lock);
        vh_ctx->status = VE_AIO_COMPLETE;
        pthread_cond_broadcast(&vh_ctx->cond);
        pthread_mutex_unlock(&vh_ctx->vh_aio_status_lock);

        /* Resource release  */
        if (0 == vh_aio_hash_delete(vh_ctx))
                free_vh_aio_ctx(vh_ctx);
        free(write_buff);
        veos_handle_free(handle);

        return NULL;
}

/**
 * @brief This function is implementation of sys_ve_aio_read()/write()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File discriptor which refer to a file this function reads from
 *               or writes to
 * @param[in] count Number of bytes read/write
 * @param[in] buff Buffer into which this function stores the read/write data
 * @param[in] offset File offset
 * @param[in] op specify which operation, read or write
 *
 * @return Return 0 on success. Negative value on failure.
 */
static int
do_aio(veos_handle *handle, struct ve_aio_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset, int op)
{
        int ret;
        struct vh_aio_ctx *vh_ctx;
        pthread_t thread;

        hash_key_t key;
        hash_value_t value;

        if (NULL == ve_ctx) {
                return -EINVAL;
        }

        vh_ctx = calloc(1, sizeof(struct vh_aio_ctx));
        if (NULL == vh_ctx) {
                PSEUDO_ERROR("VEAIO: No memory for AIO context on VH");
                return -ENOMEM;
        }

        /* Initialize vh_aio_context */
        ret = pthread_mutex_init(&vh_ctx->vh_aio_status_lock, NULL);
        if (0 != ret) {
                PSEUDO_ERROR("VEAIO: Fail to initialize mutext vh_aio_statu_lock");
                free(vh_ctx);
                return -ENOMEM;
        }
        ret = pthread_cond_init(&vh_ctx->cond, NULL);
        if (0 != ret) {
                PSEUDO_ERROR("VEAIO: Fail to initialize condition variable");
                pthread_mutex_destroy(&vh_ctx->vh_aio_status_lock);
                free(vh_ctx);
                return -ENOMEM;
        }
        /* No need to aquire lock in initialize step */
        vh_ctx->status = VE_AIO_INPROGRESS;
	vh_ctx->handle = handle;
        vh_ctx->tid = syscall(SYS_gettid);
        vh_ctx->ve_ctx = (void *)ve_ctx;
        vh_ctx->fd = fd;
        vh_ctx->buf = (uint64_t)buf;
        vh_ctx->count = count;
        vh_ctx->offset = offset;

        /* Create hash entry for VH AIO context  */
        key.type = HASH_KEY_ULONG;
        key.ul = (unsigned long)ve_ctx;
        value.type = HASH_VALUE_PTR;
        value.ptr = (void *)vh_ctx;
        /* Add entry to hash table */
        pthread_mutex_lock(&vh_aio_hash_lock);
        /* If hash table already has entry of this key, value is updated */
        ret = hash_enter(vh_aio_hash, &key, &value);
        vh_ctx->refcnt++;
        pthread_mutex_unlock(&vh_aio_hash_lock);
        switch (ret) {
        case HASH_SUCCESS:
                break;
        case HASH_ERROR_BAD_KEY_TYPE:
        case HASH_ERROR_BAD_VALUE_TYPE:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" (%s)", key.ul,
                                hash_error_string(ret));
                ret = -EINVAL;
                goto ctx_free;
        case HASH_ERROR_NO_MEMORY:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" (%s)", key.ul,
                                hash_error_string(ret));
                ret = -ENOMEM;
                goto ctx_free;
        default:
                PSEUDO_ERROR("VEAIO: Cannot add to hash table \"%lx\" unexpected (%s)",
                                key.ul, hash_error_string(ret));
                ret = -EAGAIN;
                goto ctx_free;
        }

        /* Create worker thread */
        switch (op) {
        case VE_AIO_OP_READ:
                ret = pthread_create(&thread, &thread_attr, _sys_ve_aio_read,
                                (void *)vh_ctx);
                ret = -ret;
                break;
        case VE_AIO_OP_WRITE:
                ret = pthread_create(&thread, &thread_attr, _sys_ve_aio_write,
                                (void *)vh_ctx);
                ret = -ret;
                break;
        default:
                PSEUDO_ERROR("VEAIO: Invalid AIO operation. This is unexpected");
                ret = -EAGAIN;
                break;
        }
        if (0 != ret) {
                PSEUDO_ERROR("VEAIO: Fail to create thread");
                /* Wake up thread slept by sys_ve_aio_wait() */
                pthread_mutex_lock(&vh_ctx->vh_aio_status_lock);
                vh_ctx->status = VE_AIO_COMPLETE;
                pthread_cond_broadcast(&vh_ctx->cond);
                pthread_mutex_unlock(&vh_ctx->vh_aio_status_lock);
                /* Resource release  */
                if (0 == vh_aio_hash_delete(vh_ctx))
                        free_vh_aio_ctx(vh_ctx);
        }
        return ret;

ctx_free:
        free_vh_aio_ctx(vh_ctx);
        return ret;
}

/**
 * @brief This function is handler of ve_aio_read()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File descriptor which refer to a file this function reads from
 * @param[in] count Number of bytes read
 * @param[in] buff Buffer into which this function stores the read data
 * @param[in] offset File offset
 *
 * @return Return 0 on success. Negative value on failure.
 */
int
sys_ve_aio_read(veos_handle *handle, struct ve_aio_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset)
{
        return do_aio(handle, ve_ctx, fd, count, buf, offset, VE_AIO_OP_READ);
}

/**
 * @brief This function is handler of ve_aio_write()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Context managing this request
 * @param[in] fd File discriptor
 * @param[in] count Number of bytes written
 * @param[in] buff Buffer from which this function gets the data to write
 * @param[in] offset File offset
 *
 * @return Return 0 on success. Negative value on failure.
 */
int
sys_ve_aio_write(veos_handle *handle, struct ve_aio_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset)
{
        return do_aio(handle, ve_ctx, fd, count, buf, offset, VE_AIO_OP_WRITE);
}

/**
 * @brief This function is handler of ve_aio_wait()
 *
 * @param[in] handle Handle for VE driver interface
 * @param[in] ve_ctx Address used to search vh_aio_ctx in vh_aio_hash
 *
 * @return Return 0 on success. Negative value on failure.
 **/
int
sys_ve_aio_wait(veos_handle *handle, struct ve_aio_ctx *ve_ctx)
{
        hash_key_t key;
        hash_value_t value;
        int error; /* For functions of hash table */
        struct vh_aio_ctx *vh_ctx;

        PSEUDO_DEBUG("VEAIO: enter sys_ve_aio_wait");

        if (NULL == ve_ctx)
                return -EINVAL;

        /* Create hash key  */
        key.type = HASH_KEY_ULONG;
        key.ul = (unsigned long)ve_ctx;
        /* Look up hash value in hash table  */
        pthread_mutex_lock(&vh_aio_hash_lock);
        error = hash_lookup(vh_aio_hash, &key, &value);
        switch (error) {
        case HASH_ERROR_KEY_NOT_FOUND:
                PSEUDO_DEBUG("VEAIO: can not lookup context from hash table \"%lx\" (%s)",
                                key.ul, hash_error_string(error));
                pthread_mutex_unlock(&vh_aio_hash_lock);
                return 0;
        case HASH_SUCCESS:
                vh_ctx = (struct vh_aio_ctx *)value.ptr;
                vh_ctx->refcnt++;
                pthread_mutex_unlock(&vh_aio_hash_lock);
                PSEUDO_DEBUG("VEAIO: lookup context from hash table \"%lx\" ",
                                key.ul);
                break;
        default:
                PSEUDO_ERROR("VEAIO: Unexpected error of hash table, key:\"%lx\" err:(%s)",
                                key.ul, hash_error_string(error));
                pthread_mutex_unlock(&vh_aio_hash_lock);
                return -EINVAL;
        }

        /* Check read/write status in worker thread  */
        pthread_mutex_lock(&vh_ctx->vh_aio_status_lock);
        if (VE_AIO_INPROGRESS == vh_ctx->status )
                pthread_cond_wait(&vh_ctx->cond, &vh_ctx->vh_aio_status_lock);
        pthread_mutex_unlock(&vh_ctx->vh_aio_status_lock);
        /* Delete entry from hash table  */
        if (0 == vh_aio_hash_delete(vh_ctx))
                free_vh_aio_ctx(vh_ctx);

        return 0;
}
