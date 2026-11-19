"""Pure worker-role argument parsing shared by the CLI and tests."""


DEFAULT_WORKER_ROLE = "security_checker"
LEGACY_INSTANCE_ROLES = {
    "1": "security_checker",
    "2": "security_checker",
    "3": "security_checker",
    "4": "security_checker",
}


def normalize_worker_role(value):
    role = str(value or "").strip().lower()
    if not role:
        return DEFAULT_WORKER_ROLE
    return LEGACY_INSTANCE_ROLES.get(role, role)


def resolve_worker_role(arguments, available_roles):
    if not arguments:
        role = DEFAULT_WORKER_ROLE
    else:
        if len(arguments) != 1:
            raise ValueError("exactly one worker role may be supplied")
        role = normalize_worker_role(arguments[0])

    if role not in available_roles:
        raise ValueError(f"unsupported worker role: {role}")
    return role
