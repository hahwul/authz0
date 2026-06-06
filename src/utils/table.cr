require "colorize"

module Authz0
  # Minimal text table renderer. Two output styles:
  #   * :box      — Unicode box-drawing borders (default, for terminals)
  #   * :markdown — GitHub-flavored Markdown pipe table
  #
  # Per-row coloring is supported for the box style so the scanner can paint
  # vulnerable rows red. Column widths are computed from the *visible* string
  # length (color escapes are applied after measuring).
  class Table
    enum Style
      Box
      Markdown
    end

    getter headers : Array(String)
    getter rows : Array(Array(String))

    def initialize(@headers : Array(String))
      @rows = [] of Array(String)
      @row_colors = [] of Colorize::Color?
      @aligns = Array(Symbol).new(@headers.size, :left)
    end

    # Set per-column alignment (:left or :right). Extra entries are ignored.
    def align(aligns : Array(Symbol))
      aligns.each_with_index do |a, i|
        @aligns[i] = a if i < @aligns.size
      end
      self
    end

    def add(row : Array(String), color : Colorize::Color? = nil)
      # Pad/truncate to the header arity so a short row can't desync columns.
      normalized = Array(String).new(@headers.size) { |i| row[i]? || "" }
      @rows << normalized
      @row_colors << color
      self
    end

    def render(style : Style = Style::Box, color : Bool = true) : String
      widths = column_widths
      case style
      when .markdown?
        render_markdown(widths)
      else
        render_box(widths, color)
      end
    end

    private def column_widths : Array(Int32)
      widths = @headers.map { |h| Table.display_width(h) }
      @rows.each do |row|
        row.each_with_index do |cell, i|
          w = Table.display_width(cell)
          widths[i] = w if w > widths[i]
        end
      end
      widths
    end

    # Pad based on *display* width (columns a terminal renders), not codepoint
    # count, so a column of CJK/wide glyphs still lines up with ASCII rows.
    private def pad(cell : String, width : Int32, align : Symbol) : String
      gap = width - Table.display_width(cell)
      gap = 0 if gap < 0
      align == :right ? (" " * gap) + cell : cell + (" " * gap)
    end

    # Terminal display width of a string: most East-Asian / fullwidth glyphs
    # occupy two cells, zero-width combining marks occupy none, everything
    # else one. A pragmatic subset of the Unicode East_Asian_Width table —
    # enough to keep CJK report tables aligned.
    def self.display_width(str : String) : Int32
      width = 0
      str.each_char do |c|
        cp = c.ord
        next if cp == 0
        if combining?(cp)
          # zero-width
        elsif wide?(cp)
          width += 2
        else
          width += 1
        end
      end
      width
    end

    private def self.combining?(cp : Int32) : Bool
      (0x0300 <= cp <= 0x036F) ||   # combining diacritical marks
        (0x200B <= cp <= 0x200F) || # zero-width space/joiners/marks
        (0xFE00 <= cp <= 0xFE0F)    # variation selectors
    end

    private def self.wide?(cp : Int32) : Bool
      (0x1100 <= cp <= 0x115F) ||     # Hangul Jamo
        (0x2E80 <= cp <= 0x303E) ||   # CJK radicals … symbols
        (0x3041 <= cp <= 0x33FF) ||   # Hiragana/Katakana/CJK symbols
        (0x3400 <= cp <= 0x4DBF) ||   # CJK Ext A
        (0x4E00 <= cp <= 0x9FFF) ||   # CJK Unified
        (0xA000 <= cp <= 0xA4CF) ||   # Yi
        (0xAC00 <= cp <= 0xD7A3) ||   # Hangul syllables
        (0xF900 <= cp <= 0xFAFF) ||   # CJK compatibility
        (0xFE30 <= cp <= 0xFE4F) ||   # CJK compatibility forms
        (0xFF00 <= cp <= 0xFF60) ||   # fullwidth forms
        (0xFFE0 <= cp <= 0xFFE6) ||   # fullwidth signs
        (0x1F300 <= cp <= 0x1FAFF) || # emoji & pictographs
        (0x20000 <= cp <= 0x3FFFD)    # CJK Ext B+ (supplementary)
    end

    private def render_box(widths : Array(Int32), color : Bool) : String
      String.build do |io|
        io << border(widths, "┌", "┬", "┐") << '\n'
        io << "│ " << @headers.map_with_index { |h, i| pad(h, widths[i], @aligns[i]) }.join(" │ ") << " │" << '\n'
        io << border(widths, "├", "┼", "┤") << '\n'
        @rows.each_with_index do |row, ri|
          cells = row.map_with_index { |c, i| pad(c, widths[i], @aligns[i]) }
          line = "│ " + cells.join(" │ ") + " │"
          rc = @row_colors[ri]?
          if color && rc
            io << line.colorize(rc).to_s << '\n'
          else
            io << line << '\n'
          end
        end
        io << border(widths, "└", "┴", "┘")
      end
    end

    private def border(widths : Array(Int32), left : String, mid : String, right : String) : String
      String.build do |io|
        io << left
        widths.each_with_index do |w, i|
          io << "─" * (w + 2)
          io << (i == widths.size - 1 ? right : mid)
        end
      end
    end

    private def render_markdown(widths : Array(Int32)) : String
      String.build do |io|
        io << "| " << @headers.map_with_index { |h, i| pad(h, widths[i], @aligns[i]) }.join(" | ") << " |" << '\n'
        sep = widths.map_with_index do |w, i|
          @aligns[i] == :right ? "-" * (w + 1) + ":" : "-" * (w + 2)
        end
        io << "|" << sep.join("|") << "|" << '\n'
        @rows.each_with_index do |row, ri|
          # Escape pipes inside cells so they don't break the Markdown table.
          cells = row.map_with_index { |c, i| pad(c.gsub('|', "\\|"), widths[i], @aligns[i]) }
          io << "| " << cells.join(" | ") << " |"
          io << '\n' unless ri == @rows.size - 1
        end
      end
    end
  end
end
