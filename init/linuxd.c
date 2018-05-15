#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/processor.h>

unsigned long	phys_base;
pgd_t		init_top_pgt[];
const char	early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];
unsigned long	__brk_base;
unsigned long	__brk_limit;
unsigned long	__vvar_page;
unsigned long	__iommu_table;
unsigned long	__iommu_table_end;
unsigned long	_entry_trampoline;
unsigned long	__x86_cpu_dev_start;
unsigned long	__x86_cpu_dev_end;
unsigned long	real_mode_header;
unsigned long	__apicdrivers;
unsigned long	__apicdrivers_end;
u32 *trampoline_cr4_features;
pgd_t trampoline_pgd_entry;
char __end_rodata_hpage_align[];
pmd_t level2_kernel_pgt[512];
unsigned int early_recursion_flag;
char __irqentry_text_start[], __irqentry_text_end[];
char __entry_text_start[], __entry_text_end[];
char empty_zero_page[PAGE_SIZE];

extern int printf(const char *format, ...);

int __init main(int argc, char **argv, char **envp)
{
	printf("Hello world!  This is LinuxD speaking!");

	return 0;
}
