from typing import Iterable, Callable, Optional, Any


# TODO check the same helper in standard lib
# TODO test
def search_first_in_iterable(
    it: Iterable, cond: Callable, not_found_default=None
) -> Optional[Any]:
    return next((el for el in it if cond(el)), not_found_default)
