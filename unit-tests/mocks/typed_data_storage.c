/* Transaction callback tests do not stage typed data. Real NVM cleanup is
 * exercised separately by test_typed_storage and device typed-data tests. */
#include "typed_data_storage.h"

void typed_data_storage_clear(void) {}
