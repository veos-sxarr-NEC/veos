#ifndef VEOS_AMM_ELF_DUMP_H_
#define VEOS_AMM_ELF_DUMP_H_
/**
 * @brief Structure For Note section.
 *
 *      This will contain the information about the name
 *      type , description and data of registers, signals
 *      auxv and file which will be dump in coredump
 */
struct memelfnote {
	const char *name;
	int type;
	uint64_t datasz;
	void *data;
};

enum ve_regs {
	REGSET_GENERAL,
	REGSET_FP,
};

/**
 * @brief Structure For process status.
 *
 *      This will contain the information about the pending
 *      signals, pid , ppid,  user time and general purpose
 *      register of a VE process which will be dump in
 *      coredump.
 */
struct elf_prstatus {
	struct elf_siginfo pr_info;
	short	pr_cursig;		/* Current signal */
	unsigned long pr_sigpend;	/* Set of pending signals */
	unsigned long pr_sighold;	/* Set of held signals */
	pid_t	pr_pid;
	pid_t	pr_ppid;
	pid_t	pr_pgrp;
	pid_t	pr_sid;
	struct timeval pr_utime;	/* User time */
	struct timeval pr_stime;	/* System time */
	struct timeval pr_cutime;	/* Cumulative user time */
	struct timeval pr_cstime;	/* Cumulative system time */
	unsigned long pr_reg[ELF_NGREG];/* GP registers */
	int pr_fpvalid;
};

/**
 * @brief Structure For availabe register set.
 * @name:       Identifier, e.g. UTS_MACHINE string.
 * @regsets:    Array of @n regsets available in this view.
 * @n:          Number of elements in @regsets.
 * @e_machine:  ELF header @e_machine %EM_* value written in core dumps.
 * @e_flags:    ELF header @e_flags value written in core dumps.
 * @ei_osabi:   ELF header @e_ident[%EI_OSABI] value written in core dumps.
 */
struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

/**
 * @brief Structure For accessible thred CPU state.
 *
 * @n:                  Number of slots (registers).
 * @size:               Size in bytes of a slot (register).
 * @align:              Required alignment, in bytes.
 * @bias:               Bias from natural indexing.
 * @core_note_type:     ELF note @n_type value used in core dumps.
 */
struct user_regset {
	unsigned int			n;
	unsigned int			size;
	unsigned int			align;
	unsigned int			bias;
	unsigned int			core_note_type;
};

/**
 * @brief Structure For File Backed handling.
 *
 *      This will contain the information about the file
 *      to be mapped as. Global List of this will be
 *      maintained in veos.
 */
struct core_thread {
	struct ve_task_struct *task;
	struct core_thread *next;
};


#define ELF_PRARGSZ     (80)

/**
 * @brief Structure For process information.
 *
 *      This will contain the information about the state,
 *      priority, pid , name of executable etc which will be
 *      dump in core files.
 */
struct elf_prpsinfo {
	char	pr_state;	/* numeric process state */
	char	pr_sname;	/* char for pr_state */
	char	pr_zomb;	/* zombie */
	char	pr_nice;	/* nice val */
	unsigned long pr_flag;	/* flags */
	unsigned int  pr_uid;
	unsigned int  pr_gid;
	pid_t	pr_pid, pr_ppid, pr_pgrp, pr_sid;
	/* Lots missing */
	char	pr_fname[16];	/* filename of executable */
	char	pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

/**
 * @brief Structure For process status and it task.
 *
 *      This will contain the list about the task
 *      of process, register of process which will be
 *      dump in veos.
 */
struct elf_thread_core_info {
	struct elf_thread_core_info *next;
	struct ve_task_struct *task;
	struct elf_prstatus prstatus;
	struct memelfnote notes[0];
};

/**
 * @brief Structure For Note section for core dump.
 *
 *      This will contain the information about the file
 *      auxv, signal, process info of process in core dumps.
 */
struct elf_note_info {
	struct elf_thread_core_info *thread;
	struct memelfnote psinfo;
	struct memelfnote signote;
	struct memelfnote auxv;
	struct memelfnote files;
	user_siginfo_t csigdata;
	size_t size;
	int thread_notes;
	int map_count;
};

#endif
