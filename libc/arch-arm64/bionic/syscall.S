/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <private/bionic_asm.h>
#include <sys/syscall.h>

ENTRY(__raw_syscall)
.Lraw_syscall:
    /* Move syscall No. from x0 to x8 */
    mov     x8, x0
    /* Move syscall parameters from x1 thru x6 to x0 thru x5 */
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    mov     x5, x6
    svc     #0

    /* check if syscall returned successfully */
    cmn     x0, #(MAX_ERRNO + 1)
    cneg    x0, x0, hi
    b.hi    __set_errno_internal

    ret
END(__raw_syscall)

ENTRY(syscall)
    cmp     x0, #__NR_openat
    b.eq    .Lhandle_openat
    b       .Lraw_syscall

.Lhandle_openat:
    stp     x29, x30, [sp, #-80]!
    .cfi_def_cfa_offset 80
    .cfi_offset 29, -80
    .cfi_offset 30, -72
    mov     x29, sp

    stp     x0, x1, [sp, #16]
    stp     x2, x3, [sp, #32]
    stp     x4, x5, [sp, #48]
    str     x6,     [sp, #64]

    mov     x0, x1
    mov     x1, x2
    bl      custom_rom_hide_syscall_openat

    cmp     x0, #0
    b.ge    .Lopenat_done

    cmn     x0, #2
    b.ne    .Lopenat_fallback
    mov     x0, #-1
    b       .Lopenat_done

.Lopenat_fallback:
    ldp     x0, x1, [sp, #16]
    ldp     x2, x3, [sp, #32]
    ldp     x4, x5, [sp, #48]
    ldr     x6,     [sp, #64]
    ldp     x29, x30, [sp], #80
    .cfi_def_cfa_offset 0
    .cfi_restore 29
    .cfi_restore 30
    b       .Lraw_syscall

.Lopenat_done:
    ldp     x29, x30, [sp], #80
    .cfi_def_cfa_offset 0
    .cfi_restore 29
    .cfi_restore 30
    ret
END(syscall)

NOTE_GNU_PROPERTY()
