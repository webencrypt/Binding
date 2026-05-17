/* QR-UOV-PKB self-test harness.
 *
 * Runs the selftest entry points of both PKB-T and PKB-H profiles and
 * reports per-profile pass/fail. Exits 0 only if both pass.
 *
 * Usage:
 *   ./test_qruov_pkb              # run both profiles
 *   ./test_qruov_pkb t            # PKB-T only
 *   ./test_qruov_pkb h            # PKB-H only
 */

#include <stdio.h>
#include <string.h>

#include "qruov_pkb_t.h"
#include "qruov_pkb_h.h"

static int run_t(void) {
    int rc = qruov_pkb_t_selftest();
    if (rc == 0) {
        printf("[OK]   qruov_pkb_t_selftest: round-trip + 8 negative checks pass\n");
    } else {
        printf("[FAIL] qruov_pkb_t_selftest: rc=%d\n", rc);
    }
    return rc;
}

static int run_h(void) {
    int rc = qruov_pkb_h_selftest();
    if (rc == 0) {
        printf("[OK]   qruov_pkb_h_selftest: round-trip + 7 negative checks pass\n");
    } else {
        printf("[FAIL] qruov_pkb_h_selftest: rc=%d\n", rc);
    }
    return rc;
}

int main(int argc, char *argv[]) {
    int do_t = 1, do_h = 1;
    if (argc >= 2) {
        if (strcmp(argv[1], "t") == 0) { do_t = 1; do_h = 0; }
        else if (strcmp(argv[1], "h") == 0) { do_t = 0; do_h = 1; }
    }

    int rc_t = 0, rc_h = 0;
    if (do_t) rc_t = run_t();
    if (do_h) rc_h = run_h();

    if (rc_t != 0 || rc_h != 0) {
        printf("FAILURE: rc_t=%d rc_h=%d\n", rc_t, rc_h);
        return 1;
    }
    printf("ALL PASS\n");
    return 0;
}
