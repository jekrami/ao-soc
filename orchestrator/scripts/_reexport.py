"""Pull private names through root shims. ``from x import *`` skips ``_foo``."""


def into(mod, namespace: dict) -> None:
    namespace.update({n: getattr(mod, n) for n in dir(mod) if not n.startswith('__')})
