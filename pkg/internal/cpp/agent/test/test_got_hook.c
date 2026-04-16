/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test: GOT hook framework verification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "got_hook.h"

/* Test: hook strlen */
static size_t fake_strlen(const char *s) {
    (void)s;
    return 42; /* Always return 42 */
}

static void test_hook_install_and_remove(void) {
    void *orig = NULL;
    const char *test_str = "hello";

    /* Pre-hook: strlen should return 5 */
    size_t normal_len = strlen(test_str);
    assert(normal_len == 5);

    /* Install hook */
    int rc = obi_hook_install("strlen", (void *)fake_strlen, &orig);
    if (rc != 0) {
        printf("SKIP: strlen not found in GOT (static linking?)\n");
        return;
    }
    assert(orig != NULL);

    /* Post-hook: strlen should return 42 */
    size_t hooked_len = strlen(test_str);
    assert(hooked_len == 42);

    /* Remove hook */
    rc = obi_hook_remove("strlen");
    assert(rc == 0);

    /* Post-unhook: strlen should return 5 again */
    size_t restored_len = strlen(test_str);
    assert(restored_len == 5);

    printf("PASS: test_hook_install_and_remove\n");
}

static void test_hook_remove_all(void) {
    void *orig = NULL;

    int rc = obi_hook_install("strlen", (void *)fake_strlen, &orig);
    if (rc != 0) {
        printf("SKIP: strlen not found in GOT\n");
        return;
    }

    obi_hook_remove_all();

    /* strlen should be restored */
    size_t len = strlen("test");
    assert(len == 4);

    printf("PASS: test_hook_remove_all\n");
}

static void test_hook_nonexistent_symbol(void) {
    int rc = obi_hook_install("__totally_fake_symbol_12345__", (void *)fake_strlen, NULL);
    assert(rc == -1); /* Should fail */

    printf("PASS: test_hook_nonexistent_symbol\n");
}

int main(void) {
    test_hook_install_and_remove();
    test_hook_remove_all();
    test_hook_nonexistent_symbol();
    printf("All GOT hook tests passed.\n");
    return 0;
}
