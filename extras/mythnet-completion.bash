#!/bin/bash
# Bash completion for mythnet

_mythnet_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "$prev" in
        -c|--config)
            COMPREPLY=($(compgen -f -X '!*.yaml' -- "$cur"))
            return
            ;;
        mythnet)
            COMPREPLY=($(compgen -W "--config -c --version --help" -- "$cur"))
            return
            ;;
    esac

    COMPREPLY=($(compgen -W "--config -c --version --help" -- "$cur"))
}

complete -F _mythnet_completions mythnet
