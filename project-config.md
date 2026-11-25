# Historical project-config proposal

> **Historical only.** This proposal predates the shipped interface. Do not use
> its `agent-vm config edit` guidance; follow [USAGE.md](USAGE.md#tool-configuration).

We have a concept of a user configuration (~/.config/agent-vm.toml) and then also a project configuration.
I want to overhaul how the project configuration works.

A main design point is security through intention and pinning.
The attack vector we are concerned about is a user viewing someone else's code, including a branch from another fork, etc.
We don't want the user's configuration to be changed by someone else.

By default, there should not be any project configuration.
The user must create a project configuration:

  agent-vm config edit

The project configuration would be stored either in an agent-vm state diretory or in ~/.config/agent-vm/
If the user wants to use a shared configuration, they source it from their config:

  source home:trust ~/.config/agent-vm.toml # The default first line of a project config
  source repo ./conf/agent-vm.toml

The home config is always trusted.
The project config is pinned.
When it changes, the user should be shown a diff and approve the new config, which will be added to the trusted pins.

The user can specify additional configurations in their project the same as the existing config files.
But they can use definitions from the existing files and use "home" or "repo" to disambiguate.
