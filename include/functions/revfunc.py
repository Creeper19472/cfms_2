import json
import time
from include.bulitin_class.models import FileRevisions, PathStructures
from include.experimental.singine import Session
import secrets


def addRevision(
    path_id: str,
    file_index_id: str,
    parent_rev_id: str = None,
    access_rules: dict = {},
    external_access: dict = {},
    state: int = 0,
    state_expire_time: int = 0,
    _override_existence_check = False
) -> str:
    """A function performs the adding operation for a new revision."""

    new_rev_id = secrets.token_hex(16)

    with Session() as session:

        if parent_rev_id:
            parent_rev = session.get(FileRevisions, parent_rev_id)
            if not parent_rev:
                raise RuntimeError("Specified parent revision does not exist")

        path_entry = session.get(PathStructures, path_id)
        if not path_entry and not _override_existence_check:
            raise RuntimeError("Specified path entry does not exist")

        new_revision = FileRevisions(
            rev_id=new_rev_id,
            path_id=path_id,
            file_index_id=file_index_id,
            access_rules=json.dumps(access_rules),
            external_access=json.dumps(external_access),
            state=state,
            state_expire_time=state_expire_time,
            created_time=time.time(),
        )

        session.add(new_revision)
        session.commit()

    return new_rev_id
