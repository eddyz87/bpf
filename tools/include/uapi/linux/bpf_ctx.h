/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI__LINUX_BPF_CTX_H__
#define _UAPI__LINUX_BPF_CTX_H__

#if __has_attribute(btf_decl_tag) && !defined(__cplusplus)
#define __bpf_ctx __attribute__((btf_decl_tag("ctx")))
#else
#define __bpf_ctx
#endif

#endif /* _UAPI__LINUX_BPF_CTX_H__ */
