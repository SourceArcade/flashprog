#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "fmap.h"

START_TEST(test_fmap_size_never_overflows)
{
    // Invariant: fmap_size() never causes integer overflow or returns size smaller than needed
    struct fmap test_fmaps[] = {
        {.nareas = 0},  // Valid minimal case
        {.nareas = SIZE_MAX / sizeof(struct fmap_area)},  // Boundary: maximum safe value
        {.nareas = SIZE_MAX / sizeof(struct fmap_area) + 1},  // Exploit: triggers overflow
        {.nareas = SIZE_MAX},  // Extreme: worst-case overflow
        {.nareas = 100}  // Normal valid case
    };
    
    for (unsigned i = 0; i < sizeof(test_fmaps) / sizeof(test_fmaps[0]); i++) {
        size_t computed_size = fmap_size(&test_fmaps[i]);
        
        // Property: size must be >= sizeof(struct fmap) for any valid nareas
        ck_assert_msg(computed_size >= sizeof(struct fmap),
                     "fmap_size returned %zu which is smaller than base struct size %zu for nareas=%u",
                     computed_size, sizeof(struct fmap), test_fmaps[i].nareas);
        
        // Property: if no overflow occurred, size should match expected calculation
        if (test_fmaps[i].nareas <= SIZE_MAX / sizeof(struct fmap_area)) {
            size_t expected = sizeof(struct fmap) + test_fmaps[i].nareas * sizeof(struct fmap_area);
            ck_assert_msg(computed_size == expected,
                         "fmap_size returned %zu but expected %zu for nareas=%u",
                         computed_size, expected, test_fmaps[i].nareas);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_fmap_size_never_overflows);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}