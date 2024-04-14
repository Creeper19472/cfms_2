# coding=utf-8
from __future__ import unicode_literals, absolute_import

import json
from include.bulitin_class.users import Users
from include.database.operator import DatabaseOperator

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, VARCHAR, Text

from include.experimental import singine
from include.bulitin_class.models import PathStructures

ModelBase = declarative_base()  # <-元类


class Shortcuts(ModelBase):
    __tablename__ = "shortcuts"

    short_id = Column(VARCHAR(255), primary_key=True)
    short_value = Column(VARCHAR(255))
    owner = Column(Text())


def handle_getShortcut(instance, loaded_recv, user: Users):
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not (shortcut_id := loaded_recv["data"].get("shortcut_id", None)):
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    with singine.Session() as session:
        this_shortcut = session.get(Shortcuts, shortcut_id)
        if not this_shortcut:
            instance.respond(404, "shortcut does not exist")
            return

        this_pointed_path = session.get(PathStructures, this_shortcut.short_value)

        pointed_type = None
        if this_pointed_path:
            pointed_type = this_pointed_path.type

        instance.respond(
            0,
            msg="OK",
            shortcut_value=this_shortcut.short_value,
            pointed_type=pointed_type,
        )

    return


def handle_operateShortcuts(instance, loaded_recv, user: Users):
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not (action := loaded_recv["data"].get("action", None)) or not (
        shortcut_id := loaded_recv["data"].get("shortcut_id", None)
    ):
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if action == "add":
        if not (shortcut_value := loaded_recv["data"].get("shortcut_value", None)):
            instance.respond(**instance.RES_MISSING_ARGUMENT)
            return

        if not "add_shortcuts" in user.rights:
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

        with singine.Session() as session:

            if (
                session.query(Shortcuts)
                .filter(Shortcuts.short_id == shortcut_id)
                .all()
            ):
                instance.respond(-1, "shortcut already exists")
                return

            new_shortcut = Shortcuts(
                short_id=shortcut_id,
                short_value=shortcut_value,  # Note: We don't check whether the target is valid or not.
                owner=json.dumps(("user", user.username)),
            )

            session.add(new_shortcut)
            session.commit()

        instance.respond(instance.RES_OK)
        return

    elif action == "remove":
        if not "remove_shortcuts" in user.rights:
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

        with singine.Session() as session:

            this_shortcut = session.get(Shortcuts, shortcut_id)

            if not this_shortcut:
                instance.respond(404, "shortcut does not exist")
                return

            session.delete(this_shortcut)

            session.commit()

            instance.respond(instance.RES_OK)
            return

    elif action == "rename":
        if not "rename_shortcuts" in user.rights:
            instance.respond(**instance.RES_ACCESS_DENIED)
            return
        
        ## TODO

    else:
        instance.respond(400, msg=f"invaild action for operateShortcut: {action}")
        return