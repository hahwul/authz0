require "option_parser"
require "../../utils/errors"

module Authz0::CLI
  # `authz0 completion <bash|zsh|fish>` — emit a shell completion script.
  # Static command/subcommand completion (no dynamic session-name lookup, to
  # keep it dependency-free and fast).
  class CompletionCommand
    COMMANDS = "session url cred assert scan import export doctor config completion version help"

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
        local cur prev words cword
        _init_completion 2>/dev/null || { cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"; }
        local commands="#{COMMANDS}"
        if [ "$COMP_CWORD" -eq 1 ]; then
          COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
          return
        fi
        case "${COMP_WORDS[1]}" in
          session) COMPREPLY=( $(compgen -W "new list show set delete rename clone" -- "$cur") ) ;;
          url)     COMPREPLY=( $(compgen -W "add list show update remove" -- "$cur") ) ;;
          cred)    COMPREPLY=( $(compgen -W "add list update remove" -- "$cur") ) ;;
          assert)  COMPREPLY=( $(compgen -W "add list remove" -- "$cur") ) ;;
          config)  COMPREPLY=( $(compgen -W "list get set unset" -- "$cur") ) ;;
          import)  COMPREPLY=( $(compgen -W "openapi har burp urls postman" -- "$cur") ) ;;
          export)  COMPREPLY=( $(compgen -W "yaml" -- "$cur") ) ;;
          completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
        esac
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
        if (( CURRENT == 2 )); then
          compadd -- $commands
          return
        fi
        case "${words[2]}" in
          session) compadd -- new list show set delete rename clone ;;
          url)     compadd -- add list show update remove ;;
          cred)    compadd -- add list update remove ;;
          assert)  compadd -- add list remove ;;
          config)  compadd -- list get set unset ;;
          import)  compadd -- openapi har burp urls postman ;;
          export)  compadd -- yaml ;;
          completion) compadd -- bash zsh fish ;;
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
      complete -c authz0 -n __fish_use_subcommand -a "session url cred assert scan import export doctor config completion version help"
      complete -c authz0 -n "__fish_seen_subcommand_from session" -a "new list show set delete rename clone"
      complete -c authz0 -n "__fish_seen_subcommand_from url" -a "add list show update remove"
      complete -c authz0 -n "__fish_seen_subcommand_from cred" -a "add list update remove"
      complete -c authz0 -n "__fish_seen_subcommand_from assert" -a "add list remove"
      complete -c authz0 -n "__fish_seen_subcommand_from config" -a "list get set unset"
      complete -c authz0 -n "__fish_seen_subcommand_from import" -a "openapi har burp urls postman"
      complete -c authz0 -n "__fish_seen_subcommand_from export" -a "yaml"
      complete -c authz0 -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
      FISH
    end
  end
end
