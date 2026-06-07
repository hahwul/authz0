require "option_parser"
require "../../utils/errors"

module Authz0::CLI
  # `authz0 completion <bash|zsh|fish>` — emit a shell completion script.
  # Static command/subcommand completion (no dynamic session-name lookup, to
  # keep it dependency-free and fast).
  class CompletionCommand
    COMMANDS = "session url cred assert scan results stats import export doctor config completion version help"

    def run(args : Array(String))
      shell = args.shift?
      case shell
      when "bash" then puts bash
      when "zsh"  then puts zsh
      when "fish" then puts fish
      when nil, "-h", "--help"
        puts "Usage: authz0 completion <bash|zsh|fish>"
      else
        raise ValidationError.new("unsupported shell: #{shell}", "one of: bash, zsh, fish")
      end
    end

    private def bash : String
      <<-BASH
      # authz0 bash completion — add to ~/.bashrc:
      #   source <(authz0 completion bash)
      _authz0() {
        local cur cmd az
        cur="${COMP_WORDS[COMP_CWORD]}"
        cmd="${COMP_WORDS[1]}"
        az="${COMP_WORDS[0]}"
        local commands="#{COMMANDS}"

        if [ "$COMP_CWORD" -eq 1 ]; then
          COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
          return
        fi

        # Subcommand position — or, for `scan`, the session name itself.
        if [ "$COMP_CWORD" -eq 2 ]; then
          case "$cmd" in
            session) COMPREPLY=( $(compgen -W "new list show set delete rename clone use backup restore" -- "$cur") ); return ;;
            url)     COMPREPLY=( $(compgen -W "add list show update remove" -- "$cur") ); return ;;
            cred)    COMPREPLY=( $(compgen -W "add list show update remove" -- "$cur") ); return ;;
            assert)  COMPREPLY=( $(compgen -W "add list show remove" -- "$cur") ); return ;;
            results) COMPREPLY=( $(compgen -W "list show clean" -- "$cur") ); return ;;
            config)  COMPREPLY=( $(compgen -W "list get set unset" -- "$cur") ); return ;;
            import)  COMPREPLY=( $(compgen -W "auto openapi har burp urls postman" -- "$cur") ); return ;;
            export)  COMPREPLY=( $(compgen -W "yaml" -- "$cur") ); return ;;
            completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ); return ;;
            scan)    COMPREPLY=( $(compgen -W "$("$az" session list --names 2>/dev/null)" -- "$cur") ); return ;;
          esac
        fi

        # The argument right after a subcommand names a session for these.
        if [ "$COMP_CWORD" -eq 3 ]; then
          case "$cmd" in
            url|cred|assert|results|import|export|session)
              COMPREPLY=( $(compgen -W "$("$az" session list --names 2>/dev/null)" -- "$cur") ); return ;;
          esac
        fi
      }
      complete -F _authz0 authz0
      BASH
    end

    private def zsh : String
      <<-ZSH
      #compdef authz0
      # authz0 zsh completion — add to your fpath, or:
      #   source <(authz0 completion zsh)
      _authz0() {
        local -a commands
        commands=(#{COMMANDS})
        local cmd="${words[2]}" az="${words[1]}"
        case $CURRENT in
          2) compadd -- $commands ;;
          3)
            case "$cmd" in
              session) compadd -- new list show set delete rename clone use backup restore ;;
              url)     compadd -- add list show update remove ;;
              cred)    compadd -- add list show update remove ;;
              assert)  compadd -- add list show remove ;;
              results) compadd -- list show clean ;;
              config)  compadd -- list get set unset ;;
              import)  compadd -- auto openapi har burp urls postman ;;
              export)  compadd -- yaml ;;
              completion) compadd -- bash zsh fish ;;
              scan)    compadd -- ${(f)"$($az session list --names 2>/dev/null)"} ;;
            esac ;;
          4)
            case "$cmd" in
              url|cred|assert|results|import|export|session) compadd -- ${(f)"$($az session list --names 2>/dev/null)"} ;;
            esac ;;
        esac
      }
      compdef _authz0 authz0
      ZSH
    end

    private def fish : String
      <<-FISH
      # authz0 fish completion — save to ~/.config/fish/completions/authz0.fish:
      #   authz0 completion fish > ~/.config/fish/completions/authz0.fish
      complete -c authz0 -f
      complete -c authz0 -n __fish_use_subcommand -a "session url cred assert scan results stats import export doctor config completion version help"
      complete -c authz0 -n "__fish_seen_subcommand_from session" -a "new list show set delete rename clone use backup restore"
      complete -c authz0 -n "__fish_seen_subcommand_from url" -a "add list show update remove"
      complete -c authz0 -n "__fish_seen_subcommand_from cred" -a "add list show update remove"
      complete -c authz0 -n "__fish_seen_subcommand_from assert" -a "add list show remove"
      complete -c authz0 -n "__fish_seen_subcommand_from results" -a "list show clean"
      complete -c authz0 -n "__fish_seen_subcommand_from config" -a "list get set unset"
      complete -c authz0 -n "__fish_seen_subcommand_from import" -a "auto openapi har burp urls postman"
      complete -c authz0 -n "__fish_seen_subcommand_from export" -a "yaml"
      complete -c authz0 -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
      # Session names where a session is the expected argument.
      complete -c authz0 -n "__fish_seen_subcommand_from scan" -a "(authz0 session list --names)"
      complete -c authz0 -n "__fish_seen_subcommand_from url cred assert results import export; and __fish_seen_subcommand_from add list show update remove clean auto openapi har burp urls postman yaml" -a "(authz0 session list --names)"
      complete -c authz0 -n "__fish_seen_subcommand_from session; and __fish_seen_subcommand_from show set delete rename clone use backup restore" -a "(authz0 session list --names)"
      FISH
    end
  end
end
