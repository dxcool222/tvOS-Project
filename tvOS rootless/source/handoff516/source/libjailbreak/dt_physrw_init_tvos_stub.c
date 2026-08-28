#include "physrw.h"

int libjailbreak_physrw_init(bool receivedHandoff)
{
	(void)receivedHandoff;
	/* tvOS Gate1 boomerang path uses physrw_pte only (boomerang_recoverPrimitives516). */
	return -1;
}
