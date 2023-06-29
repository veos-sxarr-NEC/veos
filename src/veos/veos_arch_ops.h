#ifndef VEOS_ARCH_OPS_H
#define VEOS_ARCH_OPS_H
#include <sys/types.h>
#include <stdbool.h>
#include <libved.h>
#include <signal.h>

#include <mm_type.h>
#include <dma.h>

struct ve_context_info;
struct ve_task_struct;
struct ve_core_struct;
struct ve_node_struct;
struct ve_thread_struct;
struct ve_udma;
struct veos_dmaatb_reg;
struct ve_dma_engine_usage;
struct vehva_header;
struct ve_acct;
struct proginf_v1;
enum acct_data;
typedef struct ve_dma_reqlist_entry ve_dma_reqlist_entry;
typedef struct ve_dma__block ve_dma__block;
#ifndef veos__pciatb_entry_defined
#define veos__pciatb_entry_defined
typedef union veos_pciatb_entry {/* pciatb_api.h */
	ve_reg_t data;
	struct {
		ve_reg_t rfu1:16, page_base_address:27, rfu2:14, num:2, sync:1,
			rfu3:2, cache_bypass:1, rfu4:1;
	} bf;
} veos_pciatb_entry_t;
#endif

#ifndef veos__atb_entry_defined
#define veos__atb_entry_defined
union veos_atb_entry {
	ve_reg_t data;
	struct { ve_reg_t reg_;} bf;
};
typedef union veos_atb_entry veos_atb_entry_t;
#endif

#ifndef veos__atb_dir_defined
#define veos__atb_dir_defined
union veos_atb_dir {
	ve_reg_t data;
	struct { ve_reg_t reg_;} bf;
};
typedef union veos_atb_dir veos_atb_dir_t;
#endif

typedef struct veos_dmaatb_reg veos_dmaatb_reg_t;
typedef struct veos_atb_reg atb_reg_t;
struct ve_mm_struct;
typedef struct vehva_header vehva_header_t;
enum swap_progress;
typedef struct cr_cluster cr_cluster_t;
#ifndef veos__crd_defined
#define veos__crd_defined
typedef union crd_t { /* veos.h */
	ve_reg_t data;
	struct {
		ve_reg_t pgnum:5, rfu:58, valid:1;
	} bf;
} crd_t;
#endif

struct ve_swapped_virtual;

struct veos_arch_ops {
	void (*arch_psm_copy_user_regs_in_thread_struct)(void *, const void *);
	void (*arch_psm_update_thread_struct)(void *, const struct ve_context_info *);
	off_t (*arch_psm_get_reg_offset)(ve_usr_reg_name_t reg);
	int (*arch_psm_save_context_from_core_reg)(ve_dma_hdl *, int, pid_t, void *);
	ve_reg_t (*arch_psm_get_PSW_from_thread_struct)(const void *);
	void (*arch_psm_set_PSW_on_thread_struct)(void *, ve_reg_t);
	void (*arch_psm_set_child_tls_desc)(void *, const void *);
	void (*arch_psm_set_stack_pointer_on_thread_struct)(void *, ve_reg_t);
	void (*arch_psm_set_retval_on_thread_struct)(void *, ve_reg_t);
	int (*arch_psm_set_thread_descriptor_area_on_stack)(pid_t, uint64_t, pid_t, const void *);
	int (*arch_psm_restore_ve_context_from_sighand)(struct ve_task_struct *);
	void *(*arch_psm_get_exception_addr_on_thread_struct)(const void *);
	int (*arch_psm_get_stack_pointer_from_core)(int, ve_reg_t *);
	ve_reg_t (*arch_psm_get_stack_pointer_on_thread_struct)(const void *);
	int (*arch_psm_setup_ve_frame)(int, struct ve_task_struct *, siginfo_t *, int);
	ve_reg_t (*arch_psm_get_retval_on_thread_struct)(const void *);
	void (*arch_psm_set_program_counter_to_restart)(void *);
	void (*arch_psm_save_scalar_registers)(ve_reg_t *, const void *, uint64_t);
	void (*arch_psm_restore_scalar_registers)(void *, const ve_reg_t *, uint64_t);
	void (*arch_psm_save_mode_registers)(ve_reg_t *, const void *, uint64_t);
	void (*arch_psm_restore_mode_registers)(void *, const ve_reg_t *, uint64_t);
	void *(*arch_psm_alloc_user_regs)(void);
	int (*arch_psm_set_reg_on_thread_struct)(void *, int, int, ve_usr_reg_name_t, ve_reg_t, uint64_t, uint64_t *, uint64_t *);
	int (*arch_psm_stop_udma)(int, uint8_t);
	int (*arch_psm_start_udma)(int, uint8_t);
	int (*arch__psm_save_udma_context)(struct ve_task_struct *, int, int);
	int (*arch__psm_restore_udma_context)(struct ve_task_struct *, int, int);
	void (*arch_psm_clear_execution_status_on_thread_struct)(struct ve_thread_struct *);
	int (*arch_psm_restore_all_context_to_core_regs)(struct ve_core_struct *, pid_t, struct ve_thread_struct *);
	ve_reg_t (*arch_psm_get_program_counter_from_thread_struct)(const void *);
	void (*arch_psm_clear_udma_context)(struct ve_udma *);
	void (*arch_psm_set_context_from_task_to_core)(struct ve_task_struct *);
	int (*arch_psm_set_jdid_from_task_to_core)(struct ve_task_struct *);
	int (*arch_psm_get_core_execution_status)(int, ve_reg_t *);
	int (*arch_psm_request_core_to_stop)(int);
	int (*arch_psm_check_core_status_is_stopped)(ve_reg_t);
	int (*arch_psm_request_core_to_start)(int);
	int (*arch_psm_check_core_status_is_running)(ve_reg_t);
	int (*arch_psm_process_dma_resource)(struct ve_task_struct *);
	int (*arch_psm_restore_context_for_new_thread)(struct ve_task_struct *);
	int (*arch_psm_update_dmaatb_dir)(vedl_common_reg_handle *, const struct veos_dmaatb_reg *, int);
	struct ve_udma *(*arch_psm_alloc_udma_context)(void);
	void (*arch_psm_free_udma_context)(struct ve_udma *);
	size_t (*arch_psm_get_context_size)(void);
	void *(*arch_vesync_map_pci_memory_window_sync_area)(vedl_handle *, struct ve_node_struct *);
	void (*arch_vesync_unmap_pci_memory_window_sync_area)(void *);
	int (*arch_vesync_commit_rdawr_order)(void);
	int (*arch_vesync_invalidate_branch_history)(int);
	int (*arch_vesync_sync_w_pci_register_area)(void);
	int (*arch_vesync_sync_r_pci_register_area)(void);
	int (*arch_alloc_veos_pci_dma_pgtables)(veos_pciatb_entry_t **, veos_dmaatb_reg_t **);
	void (*arch_free_veos_pci_dma_pgtables)(veos_pciatb_entry_t *, veos_dmaatb_reg_t *);
	void (*arch_free_veos_vehva_header_bmap)(vehva_header_t);
	void (*arch_destroy_veos_vehva_header_vehva_lock)(vehva_header_t);
	int (*arch_pg_getpb)(veos_atb_entry_t *, int);
	void (*arch_pg_setpb)(veos_atb_entry_t *, pgno_t, int);
	void (*arch_ps_setpsnum)(veos_atb_dir_t *, pgno_t, int);
	int (*arch_ps_getps)(veos_atb_dir_t *, int);
	int64_t (*arch_psnum)(int64_t, int);
	int64_t (*arch_pgentry)(int64_t, int);
	int64_t (*arch_psnum_to_vaddr)(uint64_t, int, int);
	pgno_t (*arch_pfnum)(int64_t, int);
	uint64_t (*arch_pbaddr)(pgno_t, int);
	veos_dmaatb_reg_t *(*arch_alloc_veos_dma_pgtable)(void);
	int (*arch_amm_update_dma_all_pgtable)(const veos_dmaatb_reg_t *);
	int (*arch_amm_update_pg_dir)(int, const atb_reg_t *, int);
	void (*arch_amm__dump_dmaatb)(FILE *, const veos_dmaatb_reg_t *);
	void (*arch_amm__validate_dma_pgd)(veos_dmaatb_reg_t *, dir_t, int, int, int);
	dir_t (*arch_amm__get_dma_pgd)(vehva_t, int, bool);
	void (*arch_amm_invalidate_dmaatb)(veos_dmaatb_reg_t *);
	dir_t (*arch_amm_validate_vehva)(vehva_t, int, pgno_t, struct ve_mm_struct *, int, uint8_t, jid_t, uint16_t, int);
	dir_t (*arch_amm_invalidate_vehva)(vehva_t, struct ve_mm_struct *, jid_t);
	int64_t (*arch_amm_map_dma_area_to_system_registers)(struct ve_task_struct *);
	int (*arch_amm_dma_syscall_region_is_mapped)(const struct ve_mm_struct *);
	int64_t (*arch_amm__aa_to_vehva)(const struct ve_mm_struct *, uint64_t, int);
	void (*arch_amm_free_dmaatb)(veos_dmaatb_reg_t *, enum swap_progress);
	int64_t (*arch_amm_update_dmaatb_context)(struct ve_task_struct *, int);
	int (*arch_amm_release_dmaatb_entry)(struct ve_task_struct *);
	int (*arch_amm_sync_node_dma_page_dir)(vehva_t, struct ve_mm_struct *, dir_t, jid_t);
	int (*arch_amm__map_dmades)(struct ve_task_struct *, uint64_t *, uint64_t *);
	int64_t (*arch_amm_free_dmaatb_entry_tsk)(struct ve_task_struct *, vehva_t, size_t);
	veos_dmaatb_reg_t *(*arch_amm_dup_veos_dma_pgtable)(const veos_dmaatb_reg_t *);
	void (*arch_amm_copy_veos_dma_pgtable)(veos_dmaatb_reg_t *, const veos_dmaatb_reg_t *);
	int (*arch_amm_init_cr_reg)(void);
	int (*arch_amm_set_crd)(crd_t *, int, int, size_t);
	int (*arch_amm__clear_cr_cluster)(uint64_t);
	int (*arch_amm__save_cr_cluster)(uint64_t, cr_cluster_t *);
	int (*arch_amm__restore_cr_cluster)(uint64_t, const cr_cluster_t *);
	int (*arch_amm_get_pci_crarea_address)(uint64_t *);
	size_t (*arch_amm_get_number_of_pci_pte)(void);
	int (*arch_amm_pciatb_dump)(void);
	int (*arch_amm_set_pciatb_attr)(uint64_t, uint64_t);
	int (*arch_amm_get_pci_memory_window_size)(size_t *);
	int (*arch_amm_invalidate_all_pciatb_entries)(void);
	int (*arch_amm_set_pciatb)(const veos_pciatb_entry_t *, int, int);
	int (*arch_amm_update_pciatb_entry)(const veos_pciatb_entry_t *, int);
	int (*arch_amm__set_pcisymr)(uint8_t num, uint64_t val);
	int (*arch_amm__get_pcisymr)(uint8_t num, uint64_t *val);
	int (*arch_amm__set_pcisyar)(uint8_t num, uint64_t val);
	int (*arch_amm__get_pcisyar)(uint8_t num, uint64_t *val);
	int (*arch_amm_get_pci_memory_window_address)(uint64_t *);
	int (*arch_amm_vehva_init)(struct ve_mm_struct *);
	int64_t (*arch_amm_vehva_alloc)(int, uint64_t, struct ve_mm_struct *);
	int (*arch_amm_vehva_free)(vehva_t, size_t, struct ve_task_struct *);
	int (*arch_amm_get_dma_space_swappable_size)(veos_dmaatb_reg_t *, unsigned long *);
	int (*arch_amm_veos_get_pgmode_vehva)(struct ve_task_struct *, uint64_t);
	int64_t (*arch_amm_alloc_dmaatb_entry_by_vehva_tsk)(struct ve_task_struct *, vhsaa_t *, int, int, uint64_t, bool, uint64_t);

	int (*arch_dma_addr_type_is_valid)(const char *, ve_dma_addrtype_t);
	void (*arch_dma_cancel_all_posted)(struct ve_dma_engine_usage *);
	struct ve_dma_engine_usage *(*arch_dma_alloc_usage)(vedl_handle *, vedl_common_reg_handle *);
	void (*arch_dma_init_usage)(vedl_handle *, vedl_common_reg_handle *, struct ve_dma_engine_usage *);
	void (*arch_dma_free_usage)(vedl_handle *, vedl_common_reg_handle *, struct ve_dma_engine_usage *);
	int (*arch_dma_engine_is_busy)(const struct ve_dma_engine_usage *);
	
	void (*arch_dma_intr)(ve_dma_hdl *);
	void (*arch_dma_hw_start)(vedl_common_reg_handle *);
	void (*arch_dma_hw_post_stop)(vedl_common_reg_handle *);
	int (*arch_dma_hw_clear_all_dma)(vedl_handle *, vedl_common_reg_handle *);
	int (*arch_dma_hw_engine_is_halt)(vedl_handle *, vedl_common_reg_handle *);
	int (*arch_dma_addrtype_to_hwtype)(ve_dma_addrtype_t);
	int (*arch_dma_addrtype_to_pagesize)(ve_dma_addrtype_t);
	int (*arch_dma_pin_blk)(vedl_handle *, pid_t, ve_dma_addrtype_t, int, ve_dma__block *);
	int (*arch_dma_request_mergeable)(const ve_dma_reqlist_entry *, uint64_t, uint64_t, uint64_t);
	int (*arch_dma_reqlist__entry_post)(ve_dma_reqlist_entry *);
	void (*arch_dma_reqlist_cancel)(ve_dma_req_hdl *);
	int (*arch_main_construct_node_arch_dep_data)(struct ve_node_struct *);
	void (*arch_main_free_node_arch_dep_data)(struct ve_node_struct *);

	int (*arch_pps_veos_swap_out_dmaatb)(struct ve_task_struct *);
	int (*arch_pps_allocate_new_dmaatb_dir)(struct ve_task_struct *);
	void (*arch_pps_veos_restore_registered_memory)(struct ve_task_struct *, struct ve_swapped_virtual *, pgno_t);
	int (*arch_veos_get_pgmod_by_vehva)(uint64_t);
	int (*arch_veos_swap_in_user_veshm)(struct ve_task_struct *);
	int64_t (*arch_psm_clear_PEF_in_PSW_mask)();
	int (*arch_psm_getreg_from_core)(int regid, int core_id, void *data);
	int (*arch_psm_check_reg_consistency)(struct ve_task_struct *);
	int (*arch_psm_ptrace_getvregs)(struct ve_task_struct * , pid_t ,uint64_t );
	int (*arch_psm_ptrace_setvregs)(struct ve_task_struct *, pid_t ,uint64_t  );
	int (*arch_psm_ptrace_getregs)(struct ve_task_struct *, pid_t , uint64_t );
	int (*arch_psm_ptrace_setregs)(struct ve_task_struct *, pid_t , uint64_t );
	unsigned long (*arch_copy_user_regs_to_elf_thread_info)(void *, struct ve_thread_struct *);
	void (*arch_copy_vector_regs_from_thread_struct)(void *, struct ve_thread_struct *);
	void (*arch_veos_clear_udma)(int);
	int (*arch_psm_check_valid_userreg)(int, bool *);
	void (*arch_psm_init_perf_accounting)(struct ve_task_struct * , ve_reg_t, uint64_t *, ve_usr_reg_name_t);
	int (*arch_psm_fetch_performance_registers)(struct ve_task_struct *, int **, uint64_t **);
	void (*arch_psm_get_performance_register_info)(struct ve_task_struct *tsk, uint64_t clock_val_mhz, struct proginf_v1 *);
	void (*arch_psm_wait_for_delayed_VLFA_exception)(bool, struct ve_task_struct *);
	void (*arch_psm_set_vlfa_wait)(struct ve_task_struct *);
	void (*arch_psm_clear_vlfa_wait)(struct ve_task_struct *);
	bool (*arch_psm_get_vlfa_wait)(struct ve_task_struct *);
	void (*arch_psm_log_pwr_throttle)(int core_id, bool log_power_throttling);
	void (*arch_psm_update_pwr_throttle)(int core_id, bool ctx_switch);
	void (*arch_increment_num_ve_proc)(void);
	void (*arch_decrement_num_ve_proc)(void);
	void (*arch_turn_on_clock_gating)(void);
	void (*arch_psm_free_acct)(struct ve_acct *);
	struct ve_acct *(*arch_psm_alloc_acct)();
	void (*arch_psm_free_pmc_pmmr)(struct ve_task_struct *);
	int (*arch_psm_alloc_pmc_pmmr)(struct ve_task_struct *);
	void (*arch_get_proginf_architecture)(struct proginf_v1 *);
	void (*arch_veos_update_accounting_data)(struct ve_task_struct *, enum acct_data, double);
	void (*arch_veos_prepare_acct_info)(struct ve_task_struct *);
	void (*arch_psm_reinitialize_acct)(struct ve_task_struct *);
	uint64_t (*arch_veos_acct_size)();
	void (*arch_psm_initialize_pmc)(struct ve_task_struct *, struct ve_task_struct *);
	void (*arch_psm_update_pmc_check_overflow)(struct ve_task_struct *);
	void (*arch_psm_get_performance_of_terminated_thread)(struct ve_task_struct *, struct proginf_v1 *);
	ve_reg_t (*arch_psm_get_PMMR_on_thread_struct)(struct ve_task_struct *);
	int (*arch_psm_save_performance_registers)(struct ve_task_struct *);
	void (*arch_psm_reset_perf_accounting)(struct ve_task_struct *);

	int (*arch_init_code_modification_file_info)(char *, int, int, int, int);
	int (*arch_veos_del_temporary_files)();
	void (*arch_veos_del_temporary_files_wake_up)();
	int (*arch_psm_comm_version_compare)(char *, char *);

};

extern const struct veos_arch_ops *_veos_arch_ops;
#endif
