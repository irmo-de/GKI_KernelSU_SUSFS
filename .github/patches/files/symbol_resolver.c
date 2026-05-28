#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/version.h>

#include "infra/symbol_resolver.h"

/*
 * KernelSU-Next's stock ksu_lookup_symbol() only tries the literal
 * "<name>.cfi_jt" symbol. Under kernel CFI (CONFIG_CFI_CLANG / ThinLTO) the
 * jump-table thunk for a static function is emitted with a *hashed* name like
 * "selinux_setprocattr.a489addec120aa46c3e2d4620b5c96ad.cfi_jt", so the literal
 * lookup misses it and the resolver falls back to the bare function address.
 *
 * That breaks function-table / LSM-hlist hooking (e.g. selinux_hide's
 * setprocattr hook): the LSM hook list stores the .cfi_jt thunk address, so a
 * comparison against the bare address never matches ("target ... not found in
 * head ..."). Here we additionally scan kallsyms for a "<name>.<hash>.cfi_jt"
 * (or "<name>$...cfi_jt") variant and prefer it, mirroring upstream tiann
 * KernelSU's ksu_resolve_symbol_for_functable_hook (#3469).
 */

static const char ksu_cfi_suffix[] = ".cfi_jt";
#define KSU_CFI_SUFFIX_LEN (sizeof(ksu_cfi_suffix) - 1)

struct ksu_cfi_jt_ctx {
	const char *base;
	size_t base_len;
	unsigned long addr;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int ksu_cfi_jt_cb(void *data, const char *name, unsigned long addr)
#else
static int ksu_cfi_jt_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
	struct ksu_cfi_jt_ctx *ctx = data;
	size_t name_len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	if (mod) /* only kernel symbols */
		return 0;
#endif
	if (!name || !addr)
		return 0;

	name_len = strlen(name);
	if (name_len <= ctx->base_len + KSU_CFI_SUFFIX_LEN)
		return 0;
	if (strncmp(name, ctx->base, ctx->base_len) != 0)
		return 0;
	/* expect a separator introduced by the CFI mangling */
	if (name[ctx->base_len] != '.' && name[ctx->base_len] != '$')
		return 0;
	if (strcmp(name + name_len - KSU_CFI_SUFFIX_LEN, ksu_cfi_suffix) != 0)
		return 0;

	ctx->addr = addr;
	return 1; /* stop iteration */
}

/* Lazily resolved kallsyms_on_each_symbol (not always linkable directly). */
typedef int (*ksu_on_each_symbol_fn)(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	int (*fn)(void *, const char *, unsigned long),
#else
	int (*fn)(void *, const char *, struct module *, unsigned long),
#endif
	void *data);

static unsigned long ksu_resolve_hashed_cfi_jt(const char *symbol_name, size_t symbol_len)
{
	static ksu_on_each_symbol_fn on_each_symbol;
	struct ksu_cfi_jt_ctx ctx = {
		.base = symbol_name,
		.base_len = symbol_len,
		.addr = 0,
	};

	if (!on_each_symbol)
		on_each_symbol = (ksu_on_each_symbol_fn)kallsyms_lookup_name("kallsyms_on_each_symbol");
	if (!on_each_symbol)
		return 0;

	on_each_symbol(ksu_cfi_jt_cb, &ctx);
	return ctx.addr;
}

void *ksu_lookup_symbol(const char *symbol_name)
{
	char cfi_name[KSYM_NAME_LEN];
	void *addr;
	size_t symbol_len;

	if (!symbol_name || !symbol_name[0])
		return NULL;

	symbol_len = strlen(symbol_name);

	/* If the caller already asked for a .cfi_jt name, just resolve it. */
	if (symbol_len >= KSU_CFI_SUFFIX_LEN &&
	    strcmp(symbol_name + symbol_len - KSU_CFI_SUFFIX_LEN, ksu_cfi_suffix) == 0)
		return (void *)kallsyms_lookup_name(symbol_name);

	/* 1) literal "<name>.cfi_jt" */
	if (strscpy(cfi_name, symbol_name, sizeof(cfi_name)) > 0 &&
	    symbol_len + KSU_CFI_SUFFIX_LEN + 1 <= sizeof(cfi_name)) {
		strlcat(cfi_name, ksu_cfi_suffix, sizeof(cfi_name));
		addr = (void *)kallsyms_lookup_name(cfi_name);
		if (addr)
			return addr;
	}

	/* 2) hashed "<name>.<hash>.cfi_jt" variant emitted by kernel CFI */
	addr = (void *)ksu_resolve_hashed_cfi_jt(symbol_name, symbol_len);
	if (addr)
		return addr;

	/* 3) bare symbol */
	return (void *)kallsyms_lookup_name(symbol_name);
}
