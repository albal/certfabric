from alembic import context
from sqlalchemy import create_engine, event

from certfabric.db import _set_pragmas
from certfabric.models import Base

engine = create_engine(context.config.get_main_option("sqlalchemy.url"))
event.listen(engine, "connect", _set_pragmas)

with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()
