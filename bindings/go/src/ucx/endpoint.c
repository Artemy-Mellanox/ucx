#include "endpoint.h"

#include <stdlib.h>

ucp_request_param_t *alloc_ucp_request_param(void)
{
	return calloc(1, sizeof(ucp_request_param_t));
}
