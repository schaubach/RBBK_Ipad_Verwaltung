"""Importing this package registers every route module's endpoints on core.router.api_router.

Each submodule decorates its endpoints with ``@api_router.<method>(...)`` against the single
shared router instance (core/router.py) - importing the module is what causes those decorators
to run and register the route. This __init__ collects all of them in one place so the app entry
point (main.py) only needs a single ``import routes``.
"""

from routes import (  # noqa: F401
    admin_users,
    assignments,
    auth,
    backup,
    contract_generation,
    contracts,
    data_protection,
    imports_exports,
    ipads,
    settings,
    students,
)
