from shared.capability_policy import ActionIntent


def build_action_intent(role: str, task):

    description = (
        str(getattr(task, "description", "") or "")
        .lower()
    )

    return ActionIntent(
        role=role,
        action="execute",

        target=(
            "production_database"
            if any(
                x in description
                for x in [
                    "production database",
                    "prod db",
                    "main database",
                ]
            )
            else (
                "unknown_external_endpoint"
                if any(
                    x in description
                    for x in [
                        "external endpoint",
                        "unknown api",
                        "remote endpoint",
                    ]
                )
                else ""
            )
        ),

        irreversible=any(
            x in description
            for x in [
                "deploy",
                "publish",
                "delete",
                "transfer",
                "release",
            ]
        ),

        requires_network=any(
            x in description
            for x in [
                "github",
                "api",
                "http",
                "network",
                "remote",
            ]
        ),

        requires_shell=any(
            x in description
            for x in [
                "shell",
                "command",
                "bash",
                "terminal",
            ]
        ),
    )
